require('dotenv').config();

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const { z } = require('zod');
const db = require('./database');
const { publishNotification, subscribeToNotifications } = require('./realtime');

const app = express();
const uploadDirectory = path.resolve(process.env.UPLOAD_DIR || './uploads');
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET must be set to a secret of at least 32 characters.');
}

fs.mkdirSync(uploadDirectory, { recursive: true });
app.disable('x-powered-by');
app.use(helmet());
app.use(cors({
  origin: process.env.CLIENT_ORIGIN ? process.env.CLIENT_ORIGIN.split(',').map((item) => item.trim()) : false,
}));
app.use(express.json({ limit: '1mb' }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
});
const aiLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
});
const id = () => crypto.randomUUID();
const asyncRoute = (handler) => (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const schemas = {
  register: z.object({
    name: z.string().trim().min(1).max(100),
    email: z.string().trim().email().max(254),
    password: z.string().min(8).max(72),
  }).strict(),
  login: z.object({
    email: z.string().trim().email().max(254),
    password: z.string().min(1).max(72),
  }).strict(),
  profile: z.object({
    name: z.string().trim().min(1).max(100).optional(),
    email: z.string().trim().email().max(254).optional(),
    password: z.string().min(8).max(72).optional(),
  }).strict().refine((value) => Object.keys(value).length > 0),
  project: z.object({
    name: z.string().trim().min(1).max(120),
    description: z.string().max(2000).optional().default(''),
  }).strict(),
  addMember: z.object({ email: z.string().trim().email().max(254) }).strict(),
  invitation: z.object({ email: z.string().trim().email().max(254) }).strict(),
  acceptInvitation: z.object({ token: z.string().min(32).max(256) }).strict(),
  aiGenerate: z.discriminatedUnion('kind', [
    z.object({
      kind: z.literal('description'),
      title: z.string().trim().min(1).max(200),
      context: z.string().max(4000).optional().default(''),
    }).strict(),
    z.object({
      kind: z.literal('summary'),
      text: z.string().trim().min(1).max(10000),
    }).strict(),
  ]),
  task: z.object({
    projectId: z.string().uuid(),
    title: z.string().trim().min(1).max(200),
    description: z.string().max(10000).optional().default(''),
    assigneeId: z.string().uuid().nullable().optional(),
    status: z.enum(['open', 'in_progress', 'completed']).optional().default('open'),
    priority: z.enum(['low', 'medium', 'high']).optional().default('medium'),
    dueDate: z.string().date().nullable().optional(),
  }).strict(),
  taskUpdate: z.object({
    title: z.string().trim().min(1).max(200).optional(),
    description: z.string().max(10000).optional(),
    assigneeId: z.string().uuid().nullable().optional(),
    status: z.enum(['open', 'in_progress', 'completed']).optional(),
    priority: z.enum(['low', 'medium', 'high']).optional(),
    dueDate: z.string().date().nullable().optional(),
  }).strict().refine((value) => Object.keys(value).length > 0),
  comment: z.object({ body: z.string().trim().min(1).max(5000) }).strict(),
};

function parse(schema, value) {
  const result = schema.safeParse(value);
  if (!result.success) {
    throw new HttpError(400, result.error.issues.map((issue) => `${issue.path.join('.') || 'request'}: ${issue.message}`).join('; '));
  }
  return result.data;
}

function publicUser(user) {
  return { id: user.id, name: user.name, email: user.email, createdAt: user.created_at };
}

function issueToken(userId) {
  const sessionId = id();
  const expiresIn = process.env.JWT_EXPIRES_IN || '1d';
  const token = jwt.sign({ sub: userId }, JWT_SECRET, { jwtid: sessionId, expiresIn });
  const claims = jwt.decode(token);
  db.prepare('INSERT INTO auth_sessions (id, user_id, expires_at) VALUES (?, ?, ?)')
    .run(sessionId, userId, claims.exp);
  return token;
}

function authenticate(req, res, next) {
  const authorization = req.get('authorization');
  if (!authorization || !authorization.startsWith('Bearer ')) {
    return next(new HttpError(401, 'Authentication required.'));
  }
  try {
    const claims = jwt.verify(authorization.slice(7), JWT_SECRET);
    const session = db.prepare(`
      SELECT s.id, s.user_id, u.id AS userId, u.name, u.email, u.created_at
      FROM auth_sessions s JOIN users u ON u.id = s.user_id
      WHERE s.id = ? AND s.user_id = ? AND s.revoked_at IS NULL AND s.expires_at > ?
    `).get(claims.jti, claims.sub, Math.floor(Date.now() / 1000));
    if (!session) throw new HttpError(401, 'Session is invalid or has been logged out.');
    req.sessionId = session.id;
    req.user = { id: session.userId, name: session.name, email: session.email, created_at: session.created_at };
    return next();
  } catch (error) {
    return next(error instanceof HttpError ? error : new HttpError(401, 'Invalid or expired token.'));
  }
}

function projectRole(projectId, userId) {
  return db.prepare('SELECT role FROM project_members WHERE project_id = ? AND user_id = ?').get(projectId, userId);
}

function requireProjectMember(projectId, userId) {
  const membership = projectRole(projectId, userId);
  if (!membership) throw new HttpError(404, 'Project not found.');
  return membership;
}

function loadTask(taskId, userId) {
  const task = db.prepare('SELECT * FROM tasks WHERE id = ?').get(taskId);
  if (!task || !projectRole(task.project_id, userId)) throw new HttpError(404, 'Task not found.');
  return task;
}

function validateAssignee(projectId, assigneeId) {
  if (assigneeId && !projectRole(projectId, assigneeId)) {
    throw new HttpError(400, 'Assignee must be a member of the task project.');
  }
}

function formatTask(task) {
  return {
    id: task.id,
    projectId: task.project_id,
    creatorId: task.creator_id,
    assigneeId: task.assignee_id,
    title: task.title,
    description: task.description,
    status: task.status,
    priority: task.priority,
    dueDate: task.due_date,
    createdAt: task.created_at,
    updatedAt: task.updated_at,
  };
}

function createNotification({ userId, projectId, taskId = null, actorId, type, title, message }) {
  const notificationId = id();
  db.prepare(`
    INSERT INTO notifications (id, user_id, project_id, task_id, actor_id, type, title, message)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(notificationId, userId, projectId, taskId, actorId, type, title, message);
  const notification = db.prepare('SELECT * FROM notifications WHERE id = ?').get(notificationId);
  publishNotification(userId, {
    id: notification.id,
    type: notification.type,
    title: notification.title,
    message: notification.message,
    projectId: notification.project_id,
    taskId: notification.task_id,
    actorId: notification.actor_id,
    readAt: notification.read_at,
    createdAt: notification.created_at,
  });
  return notification;
}

function notifyProjectMembers(projectId, actorId, notification, excludedUserIds = []) {
  const excluded = new Set([actorId, ...excludedUserIds]);
  const members = db.prepare('SELECT user_id FROM project_members WHERE project_id = ?').all(projectId);
  for (const member of members) {
    if (!excluded.has(member.user_id)) createNotification({ ...notification, userId: member.user_id });
  }
}

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.post('/api/auth/register', authLimiter, (req, res) => {
  const input = parse(schemas.register, req.body);
  const userId = id();
  const passwordHash = bcrypt.hashSync(input.password, 12);
  try {
    db.prepare('INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)')
      .run(userId, input.email.toLowerCase(), input.name, passwordHash);
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') throw new HttpError(409, 'An account with this email already exists.');
    throw error;
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  res.status(201).json({ user: publicUser(user), token: issueToken(userId) });
});

app.post('/api/auth/login', authLimiter, (req, res) => {
  const input = parse(schemas.login, req.body);
  const user = db.prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE').get(input.email);
  if (!user || !bcrypt.compareSync(input.password, user.password_hash)) {
    throw new HttpError(401, 'Invalid email or password.');
  }
  res.json({ user: publicUser(user), token: issueToken(user.id) });
});

app.use('/api', authenticate);

app.post('/api/auth/logout', (req, res) => {
  db.prepare("UPDATE auth_sessions SET revoked_at = datetime('now') WHERE id = ?").run(req.sessionId);
  res.status(204).end();
});

app.get('/api/users/me', (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.patch('/api/users/me', (req, res) => {
  const input = parse(schemas.profile, req.body);
  const updates = [];
  const values = [];
  if (input.name !== undefined) { updates.push('name = ?'); values.push(input.name); }
  if (input.email !== undefined) { updates.push('email = ?'); values.push(input.email.toLowerCase()); }
  if (input.password !== undefined) { updates.push('password_hash = ?'); values.push(bcrypt.hashSync(input.password, 12)); }
  updates.push("updated_at = datetime('now')");
  values.push(req.user.id);
  try {
    db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...values);
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') throw new HttpError(409, 'An account with this email already exists.');
    throw error;
  }
  res.json({ user: publicUser(db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id)) });
});

app.get('/api/projects', (req, res) => {
  const projects = db.prepare(`
    SELECT p.*, pm.role FROM projects p
    JOIN project_members pm ON pm.project_id = p.id
    WHERE pm.user_id = ? ORDER BY p.created_at DESC
  `).all(req.user.id);
  res.json({ projects: projects.map((project) => ({
    id: project.id, name: project.name, description: project.description,
    ownerId: project.owner_id, role: project.role, createdAt: project.created_at,
  })) });
});

app.post('/api/projects', (req, res) => {
  const input = parse(schemas.project, req.body);
  const projectId = id();
  const createProject = db.transaction(() => {
    db.prepare('INSERT INTO projects (id, name, description, owner_id) VALUES (?, ?, ?, ?)')
      .run(projectId, input.name, input.description, req.user.id);
    db.prepare("INSERT INTO project_members (project_id, user_id, role) VALUES (?, ?, 'owner')")
      .run(projectId, req.user.id);
  });
  createProject();
  res.status(201).json({ project: {
    id: projectId, name: input.name, description: input.description, ownerId: req.user.id, role: 'owner',
  } });
});

app.get('/api/projects/:projectId/members', (req, res) => {
  requireProjectMember(req.params.projectId, req.user.id);
  const members = db.prepare(`
    SELECT u.id, u.name, u.email, pm.role, pm.joined_at
    FROM project_members pm JOIN users u ON u.id = pm.user_id
    WHERE pm.project_id = ? ORDER BY pm.joined_at
  `).all(req.params.projectId);
  res.json({ members: members.map((member) => ({
    id: member.id, name: member.name, email: member.email, role: member.role, joinedAt: member.joined_at,
  })) });
});

app.post('/api/projects/:projectId/members', (req, res) => {
  const membership = requireProjectMember(req.params.projectId, req.user.id);
  if (membership.role !== 'owner') throw new HttpError(403, 'Only the project owner can add members.');
  const input = parse(schemas.addMember, req.body);
  const user = db.prepare('SELECT id, name, email FROM users WHERE email = ? COLLATE NOCASE').get(input.email);
  if (!user) throw new HttpError(404, 'No user account exists with that email.');
  try {
    db.prepare("INSERT INTO project_members (project_id, user_id, role) VALUES (?, ?, 'member')")
      .run(req.params.projectId, user.id);
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_PRIMARYKEY') throw new HttpError(409, 'User is already a project member.');
    throw error;
  }
  res.status(201).json({ member: { ...user, role: 'member' } });
});

app.get('/api/projects/:projectId/invitations', (req, res) => {
  const membership = requireProjectMember(req.params.projectId, req.user.id);
  if (membership.role !== 'owner') throw new HttpError(403, 'Only the project owner can view invitations.');
  const invitations = db.prepare(`
    SELECT id, project_id, email, inviter_id, expires_at, accepted_at, revoked_at, created_at
    FROM project_invitations WHERE project_id = ? ORDER BY created_at DESC
  `).all(req.params.projectId);
  res.json({ invitations: invitations.map((invitation) => ({
    id: invitation.id,
    projectId: invitation.project_id,
    email: invitation.email,
    inviterId: invitation.inviter_id,
    expiresAt: new Date(invitation.expires_at * 1000).toISOString(),
    acceptedAt: invitation.accepted_at,
    revokedAt: invitation.revoked_at,
    createdAt: invitation.created_at,
  })) });
});

app.post('/api/projects/:projectId/invitations', (req, res) => {
  const membership = requireProjectMember(req.params.projectId, req.user.id);
  if (membership.role !== 'owner') throw new HttpError(403, 'Only the project owner can invite members.');
  const input = parse(schemas.invitation, req.body);
  const email = input.email.toLowerCase();
  const existingUser = db.prepare('SELECT id FROM users WHERE email = ? COLLATE NOCASE').get(email);
  if (existingUser && projectRole(req.params.projectId, existingUser.id)) {
    throw new HttpError(409, 'That user is already a project member.');
  }
  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const expiresAt = Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60);
  const invitationId = id();
  db.prepare(`
    INSERT INTO project_invitations (id, project_id, email, token_hash, inviter_id, expires_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(invitationId, req.params.projectId, email, tokenHash, req.user.id, expiresAt);
  res.status(201).json({
    invitation: {
      id: invitationId,
      projectId: req.params.projectId,
      email,
      expiresAt: new Date(expiresAt * 1000).toISOString(),
      token,
    },
  });
});

app.delete('/api/projects/:projectId/invitations/:invitationId', (req, res) => {
  const membership = requireProjectMember(req.params.projectId, req.user.id);
  if (membership.role !== 'owner') throw new HttpError(403, 'Only the project owner can revoke invitations.');
  const invitation = db.prepare(`
    SELECT id FROM project_invitations
    WHERE id = ? AND project_id = ? AND accepted_at IS NULL AND revoked_at IS NULL
  `).get(req.params.invitationId, req.params.projectId);
  if (!invitation) throw new HttpError(404, 'Pending invitation not found.');
  db.prepare("UPDATE project_invitations SET revoked_at = datetime('now') WHERE id = ?").run(invitation.id);
  res.status(204).end();
});

app.post('/api/invitations/accept', (req, res) => {
  const input = parse(schemas.acceptInvitation, req.body);
  const tokenHash = crypto.createHash('sha256').update(input.token).digest('hex');
  const invitation = db.prepare(`
    SELECT i.*, p.name AS project_name
    FROM project_invitations i JOIN projects p ON p.id = i.project_id
    WHERE i.token_hash = ? AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > ?
  `).get(tokenHash, Math.floor(Date.now() / 1000));
  if (!invitation) throw new HttpError(404, 'Invitation is invalid, expired, or revoked.');
  if (invitation.email.toLowerCase() !== req.user.email.toLowerCase()) {
    throw new HttpError(403, 'Sign in with the email address this invitation was sent to.');
  }
  if (projectRole(invitation.project_id, req.user.id)) {
    throw new HttpError(409, 'You are already a project member.');
  }
  const accept = db.transaction(() => {
    db.prepare("INSERT INTO project_members (project_id, user_id, role) VALUES (?, ?, 'member')")
      .run(invitation.project_id, req.user.id);
    db.prepare("UPDATE project_invitations SET accepted_at = datetime('now') WHERE id = ?")
      .run(invitation.id);
  });
  accept();
  createNotification({
    userId: invitation.inviter_id,
    projectId: invitation.project_id,
    actorId: req.user.id,
    type: 'project_member_joined',
    title: 'Invitation accepted',
    message: `${req.user.name} joined ${invitation.project_name}.`,
  });
  res.status(200).json({ project: {
    id: invitation.project_id,
    name: invitation.project_name,
    role: 'member',
  } });
});

app.get('/api/notifications', (req, res) => {
  const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 50, 1), 100);
  const unreadOnly = req.query.unreadOnly === 'true';
  const notifications = db.prepare(`
    SELECT id, type, title, message, project_id, task_id, actor_id, read_at, created_at
    FROM notifications WHERE user_id = ? ${unreadOnly ? 'AND read_at IS NULL' : ''}
    ORDER BY created_at DESC, id DESC LIMIT ?
  `).all(req.user.id, limit);
  res.json({ notifications: notifications.map((notification) => ({
    id: notification.id,
    type: notification.type,
    title: notification.title,
    message: notification.message,
    projectId: notification.project_id,
    taskId: notification.task_id,
    actorId: notification.actor_id,
    readAt: notification.read_at,
    createdAt: notification.created_at,
  })) });
});

app.patch('/api/notifications/:notificationId/read', (req, res) => {
  const notification = db.prepare('SELECT id FROM notifications WHERE id = ? AND user_id = ?')
    .get(req.params.notificationId, req.user.id);
  if (!notification) throw new HttpError(404, 'Notification not found.');
  db.prepare("UPDATE notifications SET read_at = datetime('now') WHERE id = ? AND read_at IS NULL")
    .run(notification.id);
  res.status(204).end();
});

app.post('/api/notifications/read-all', (req, res) => {
  db.prepare("UPDATE notifications SET read_at = datetime('now') WHERE user_id = ? AND read_at IS NULL")
    .run(req.user.id);
  res.status(204).end();
});

app.get('/api/notifications/stream', (req, res) => {
  res.status(200);
  res.set({
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();
  res.write('event: ready\ndata: {}\n\n');
  const unsubscribe = subscribeToNotifications(req.user.id, (notification) => {
    res.write(`id: ${notification.id}\nevent: notification\ndata: ${JSON.stringify(notification)}\n\n`);
  });
  const heartbeat = setInterval(() => res.write(': keep-alive\n\n'), 25000);
  res.on('close', () => {
    clearInterval(heartbeat);
    unsubscribe();
  });
});

app.post('/api/ai/generate', aiLimiter, asyncRoute(async (req, res) => {
  if (!process.env.AI_API_KEY) throw new HttpError(503, 'AI generation is not configured. Set AI_API_KEY to enable it.');
  const input = parse(schemas.aiGenerate, req.body);
  const prompt = input.kind === 'description'
    ? `Write a concise, actionable task description for the task titled "${input.title}".${input.context ? ` Additional context: ${input.context}` : ''} Return only the description.`
    : `Summarize the following task or project information clearly and concisely. Return only the summary:\n\n${input.text}`;
  const configuredBaseUrl = (process.env.AI_BASE_URL || 'https://api.openai.com/v1').replace(/\/+$/, '');
  const endpoint = configuredBaseUrl.endsWith('/chat/completions')
    ? configuredBaseUrl
    : `${configuredBaseUrl}/chat/completions`;
  let response;
  try {
    response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.AI_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: process.env.AI_MODEL || 'gpt-4o-mini',
        messages: [
          { role: 'system', content: 'You help teams write useful, clear task-management content.' },
          { role: 'user', content: prompt },
        ],
        temperature: 0.4,
        max_tokens: 700,
      }),
      signal: AbortSignal.timeout(30000),
    });
  } catch (error) {
    throw new HttpError(502, 'The AI provider could not be reached.');
  }
  if (!response.ok) throw new HttpError(502, 'The AI provider rejected the generation request.');
  let providerResult;
  try {
    providerResult = await response.json();
  } catch (error) {
    throw new HttpError(502, 'The AI provider returned an invalid response.');
  }
  const generatedText = providerResult.choices?.[0]?.message?.content;
  if (typeof generatedText !== 'string' || !generatedText.trim()) {
    throw new HttpError(502, 'The AI provider returned no generated content.');
  }
  res.json({ kind: input.kind, text: generatedText.trim(), model: process.env.AI_MODEL || 'gpt-4o-mini' });
}));

app.get('/api/tasks', (req, res) => {
  const filters = [];
  const values = [req.user.id];
  if (req.query.projectId) {
    if (!z.string().uuid().safeParse(req.query.projectId).success) throw new HttpError(400, 'projectId must be a UUID.');
    filters.push('t.project_id = ?');
    values.push(req.query.projectId);
  }
  if (req.query.status) {
    if (!['open', 'in_progress', 'completed'].includes(req.query.status)) throw new HttpError(400, 'Invalid status filter.');
    filters.push('t.status = ?');
    values.push(req.query.status);
  }
  if (req.query.assignedTo === 'me') {
    filters.push('t.assignee_id = ?');
    values.push(req.user.id);
  } else if (req.query.assignedTo) {
    if (!z.string().uuid().safeParse(req.query.assignedTo).success) throw new HttpError(400, 'assignedTo must be a UUID or "me".');
    filters.push('t.assignee_id = ?');
    values.push(req.query.assignedTo);
  }
  if (req.query.q) {
    const query = String(req.query.q).trim().slice(0, 200);
    filters.push("(instr(lower(t.title), lower(?)) > 0 OR instr(lower(t.description), lower(?)) > 0)");
    values.push(query, query);
  }
  const allowedSort = { createdAt: 't.created_at', dueDate: 't.due_date', title: 't.title', priority: "CASE t.priority WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END", status: 't.status' };
  const sortBy = req.query.sortBy || 'createdAt';
  if (!Object.hasOwn(allowedSort, sortBy)) throw new HttpError(400, 'Invalid sortBy value.');
  const order = req.query.order || 'desc';
  if (!['asc', 'desc'].includes(order)) throw new HttpError(400, 'order must be asc or desc.');
  const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 50, 1), 100);
  const offset = Math.max(Number.parseInt(req.query.offset, 10) || 0, 0);
  const where = filters.length ? `AND ${filters.join(' AND ')}` : '';
  const tasks = db.prepare(`
    SELECT t.* FROM tasks t JOIN project_members pm ON pm.project_id = t.project_id
    WHERE pm.user_id = ? ${where}
    ORDER BY ${allowedSort[sortBy]} ${order.toUpperCase()}, t.id ASC LIMIT ? OFFSET ?
  `).all(...values, limit, offset);
  res.json({ tasks: tasks.map(formatTask), limit, offset });
});

app.post('/api/tasks', (req, res) => {
  const input = parse(schemas.task, req.body);
  requireProjectMember(input.projectId, req.user.id);
  validateAssignee(input.projectId, input.assigneeId);
  const taskId = id();
  db.prepare(`
    INSERT INTO tasks (id, project_id, creator_id, assignee_id, title, description, status, priority, due_date)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(taskId, input.projectId, req.user.id, input.assigneeId || null, input.title, input.description, input.status, input.priority, input.dueDate || null);
  notifyProjectMembers(input.projectId, req.user.id, {
    projectId: input.projectId,
    taskId,
    actorId: req.user.id,
    type: 'task_created',
    title: 'Task created',
    message: `${req.user.name} created "${input.title}".`,
  }, input.assigneeId ? [input.assigneeId] : []);
  if (input.assigneeId && input.assigneeId !== req.user.id) {
    createNotification({
      userId: input.assigneeId,
      projectId: input.projectId,
      taskId,
      actorId: req.user.id,
      type: 'task_assigned',
      title: 'Task assigned to you',
      message: `${req.user.name} assigned "${input.title}" to you.`,
    });
  }
  res.status(201).json({ task: formatTask(db.prepare('SELECT * FROM tasks WHERE id = ?').get(taskId)) });
});

app.get('/api/tasks/:taskId', (req, res) => {
  const task = loadTask(req.params.taskId, req.user.id);
  res.json({ task: formatTask(task) });
});

app.patch('/api/tasks/:taskId', (req, res) => {
  const task = loadTask(req.params.taskId, req.user.id);
  const input = parse(schemas.taskUpdate, req.body);
  if (input.assigneeId !== undefined) validateAssignee(task.project_id, input.assigneeId);
  const columns = {
    title: 'title', description: 'description', assigneeId: 'assignee_id',
    status: 'status', priority: 'priority', dueDate: 'due_date',
  };
  const updates = [];
  const values = [];
  for (const [key, column] of Object.entries(columns)) {
    if (input[key] !== undefined) { updates.push(`${column} = ?`); values.push(input[key]); }
  }
  updates.push("updated_at = datetime('now')");
  values.push(task.id);
  db.prepare(`UPDATE tasks SET ${updates.join(', ')} WHERE id = ?`).run(...values);
  const updatedTask = db.prepare('SELECT * FROM tasks WHERE id = ?').get(task.id);
  const assigneeChanged = input.assigneeId !== undefined && input.assigneeId !== task.assignee_id;
  notifyProjectMembers(task.project_id, req.user.id, {
    projectId: task.project_id,
    taskId: task.id,
    actorId: req.user.id,
    type: 'task_updated',
    title: 'Task updated',
    message: `${req.user.name} updated "${updatedTask.title}".`,
  }, assigneeChanged && input.assigneeId ? [input.assigneeId] : []);
  if (assigneeChanged && input.assigneeId && input.assigneeId !== req.user.id) {
    createNotification({
      userId: input.assigneeId,
      projectId: task.project_id,
      taskId: task.id,
      actorId: req.user.id,
      type: 'task_assigned',
      title: 'Task assigned to you',
      message: `${req.user.name} assigned "${updatedTask.title}" to you.`,
    });
  }
  res.json({ task: formatTask(updatedTask) });
});

app.delete('/api/tasks/:taskId', (req, res) => {
  const task = loadTask(req.params.taskId, req.user.id);
  const membership = projectRole(task.project_id, req.user.id);
  if (task.creator_id !== req.user.id && membership.role !== 'owner') {
    throw new HttpError(403, 'Only the task creator or project owner can delete this task.');
  }
  db.prepare('DELETE FROM tasks WHERE id = ?').run(task.id);
  res.status(204).end();
});

app.get('/api/tasks/:taskId/comments', (req, res) => {
  loadTask(req.params.taskId, req.user.id);
  const comments = db.prepare(`
    SELECT c.*, u.name AS author_name FROM comments c
    JOIN users u ON u.id = c.user_id WHERE c.task_id = ? ORDER BY c.created_at ASC
  `).all(req.params.taskId);
  res.json({ comments: comments.map((comment) => ({
    id: comment.id, taskId: comment.task_id, userId: comment.user_id,
    authorName: comment.author_name, body: comment.body, createdAt: comment.created_at,
  })) });
});

app.post('/api/tasks/:taskId/comments', (req, res) => {
  const task = loadTask(req.params.taskId, req.user.id);
  const input = parse(schemas.comment, req.body);
  const commentId = id();
  db.prepare('INSERT INTO comments (id, task_id, user_id, body) VALUES (?, ?, ?, ?)')
    .run(commentId, req.params.taskId, req.user.id, input.body);
  notifyProjectMembers(task.project_id, req.user.id, {
    projectId: task.project_id,
    taskId: task.id,
    actorId: req.user.id,
    type: 'task_commented',
    title: 'New task comment',
    message: `${req.user.name} commented on "${task.title}".`,
  });
  res.status(201).json({ comment: {
    id: commentId, taskId: req.params.taskId, userId: req.user.id,
    authorName: req.user.name, body: input.body,
    createdAt: db.prepare('SELECT created_at FROM comments WHERE id = ?').get(commentId).created_at,
  } });
});

const upload = multer({
  storage: multer.diskStorage({
    destination: uploadDirectory,
    filename: (req, file, callback) => callback(null, crypto.randomUUID()),
  }),
  limits: { fileSize: 10 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, callback) => {
    const allowed = new Set([
      'application/pdf', 'image/jpeg', 'image/png', 'image/gif', 'image/webp',
      'text/plain', 'text/csv',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    ]);
    if (!allowed.has(file.mimetype)) return callback(new HttpError(400, 'Unsupported attachment type.'));
    return callback(null, true);
  },
});

app.get('/api/tasks/:taskId/attachments', (req, res) => {
  loadTask(req.params.taskId, req.user.id);
  const attachments = db.prepare('SELECT id, task_id, uploader_id, original_name, mime_type, size, created_at FROM attachments WHERE task_id = ? ORDER BY created_at')
    .all(req.params.taskId);
  res.json({ attachments: attachments.map((file) => ({
    id: file.id, taskId: file.task_id, uploaderId: file.uploader_id,
    name: file.original_name, mimeType: file.mime_type, size: file.size, createdAt: file.created_at,
    downloadUrl: `/api/attachments/${file.id}`,
  })) });
});

app.post('/api/tasks/:taskId/attachments', (req, res, next) => {
  try { loadTask(req.params.taskId, req.user.id); } catch (error) { return next(error); }
  return upload.single('file')(req, res, (error) => {
    if (error) return next(error);
    if (!req.file) return next(new HttpError(400, 'Provide a file in the "file" field.'));
    const attachmentId = id();
    try {
      db.prepare(`
        INSERT INTO attachments (id, task_id, uploader_id, storage_name, original_name, mime_type, size)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(attachmentId, req.params.taskId, req.user.id, req.file.filename, path.basename(req.file.originalname), req.file.mimetype, req.file.size);
    } catch (insertError) {
      fs.unlink(req.file.path, (unlinkError) => { if (unlinkError) console.error('Unable to remove unreferenced upload:', unlinkError); });
      return next(insertError);
    }
    return res.status(201).json({ attachment: {
      id: attachmentId, taskId: req.params.taskId, uploaderId: req.user.id,
      name: path.basename(req.file.originalname), mimeType: req.file.mimetype, size: req.file.size,
      downloadUrl: `/api/attachments/${attachmentId}`,
    } });
  });
});

app.get('/api/attachments/:attachmentId', (req, res, next) => {
  const attachment = db.prepare('SELECT * FROM attachments WHERE id = ?').get(req.params.attachmentId);
  if (!attachment) return next(new HttpError(404, 'Attachment not found.'));
  try { loadTask(attachment.task_id, req.user.id); } catch (error) { return next(error); }
  const filePath = path.join(uploadDirectory, attachment.storage_name);
  if (!fs.existsSync(filePath)) return next(new HttpError(404, 'Attachment file is missing from storage.'));
  res.type(attachment.mime_type);
  res.attachment(attachment.original_name);
  return res.sendFile(filePath);
});

app.use((req, res, next) => next(new HttpError(404, 'Route not found.')));
app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  if (error instanceof SyntaxError && 'body' in error) {
    return res.status(400).json({ error: 'Request body must be valid JSON.' });
  }
  const status = error.status || (error.code === 'LIMIT_FILE_SIZE' ? 413 : 500);
  if (status >= 500) console.error(error);
  return res.status(status).json({
    error: status === 413 ? 'Attachment exceeds the 10 MB limit.' : (status >= 500 ? 'Internal server error.' : error.message),
  });
});

module.exports = app;
