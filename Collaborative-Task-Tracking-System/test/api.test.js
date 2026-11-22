const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const testDatabaseFile = path.resolve('./data', `test-${process.pid}.sqlite`);
process.env.JWT_SECRET = 'test-secret-that-is-at-least-thirty-two-characters';
process.env.DATABASE_FILE = testDatabaseFile;
process.env.UPLOAD_DIR = './uploads/test';
const app = require('../src/app');
const db = require('../src/database');

process.on('exit', () => {
  db.close();
  for (const file of [testDatabaseFile, `${testDatabaseFile}-shm`, `${testDatabaseFile}-wal`, `${testDatabaseFile}.tmp`]) {
    const target = path.resolve(file);
    if (fs.existsSync(target)) fs.unlinkSync(target);
  }
  const uploadPath = path.resolve('./uploads/test');
  if (fs.existsSync(uploadPath)) fs.rmSync(uploadPath, { recursive: true, force: true });
});

test('users can collaborate on tasks and logout revokes their session', async () => {
  await db.initialize();
  const registered = await request(app).post('/api/auth/register').send({
    name: 'Ada Lovelace', email: 'ada@example.com', password: 'secure-password-123',
  }).expect(201);
  const token = registered.body.token;
  const auth = { Authorization: `Bearer ${token}` };

  await request(app).get('/api/users/me').set(auth).expect(200);
  const projectResponse = await request(app).post('/api/projects').set(auth).send({
    name: 'Launch', description: 'Release project',
  }).expect(201);
  const projectId = projectResponse.body.project.id;

  const secondUser = await request(app).post('/api/auth/register').send({
    name: 'Grace Hopper', email: 'grace@example.com', password: 'another-password-123',
  }).expect(201);
  await request(app).post(`/api/projects/${projectId}/members`).set(auth)
    .send({ email: 'grace@example.com' }).expect(201);

  const taskResponse = await request(app).post('/api/tasks').set(auth).send({
    projectId, title: 'Ship the API', description: 'Finish the backend', assigneeId: secondUser.body.user.id,
    dueDate: '2027-01-15',
  }).expect(201);
  const taskId = taskResponse.body.task.id;

  await request(app).post(`/api/tasks/${taskId}/comments`).set(auth)
    .send({ body: 'I added the initial task.' }).expect(201);
  const attachment = await request(app).post(`/api/tasks/${taskId}/attachments`).set(auth)
    .attach('file', Buffer.from('release notes'), { filename: 'notes.txt', contentType: 'text/plain' }).expect(201);
  await request(app).get(`/api/tasks/${taskId}/attachments`).set(auth).expect(200);
  const downloaded = await request(app).get(attachment.body.attachment.downloadUrl).set(auth).expect(200);
  assert.equal(downloaded.text, 'release notes');
  await request(app).patch(`/api/tasks/${taskId}`).set({ Authorization: `Bearer ${secondUser.body.token}` })
    .send({ status: 'completed' }).expect(200);
  const assignedTasks = await request(app).get('/api/tasks?assignedTo=me').set({ Authorization: `Bearer ${secondUser.body.token}` }).expect(200);
  assert.equal(assignedTasks.body.tasks.length, 1);
  const filtered = await request(app).get('/api/tasks?status=completed&q=ship').set(auth).expect(200);
  assert.equal(filtered.body.tasks.length, 1);
  assert.equal(filtered.body.tasks[0].status, 'completed');
  await request(app).get(`/api/tasks/${taskId}/comments`).set(auth).expect(200);

  await request(app).post('/api/auth/logout').set(auth).expect(204);
  await request(app).get('/api/users/me').set(auth).expect(401);
});

test('invalid input and unauthorized task access are rejected', async () => {
  await db.initialize();
  const user = await request(app).post('/api/auth/register').send({
    name: 'Linus Torvalds', email: 'linus@example.com', password: 'long-password-456',
  }).expect(201);
  const auth = { Authorization: `Bearer ${user.body.token}` };

  await request(app).post('/api/tasks').set(auth).send({
    projectId: 'not-a-uuid', title: '',
  }).expect(400);

  const other = await request(app).post('/api/auth/register').send({
    name: 'Katherine Johnson', email: 'katherine@example.com', password: 'long-password-789',
  }).expect(201);
  const project = await request(app).post('/api/projects').set(auth).send({ name: 'Private project' }).expect(201);
  const task = await request(app).post('/api/tasks').set(auth).send({
    projectId: project.body.project.id, title: 'Private task',
  }).expect(201);
  await request(app).get(`/api/tasks/${task.body.task.id}`)
    .set({ Authorization: `Bearer ${other.body.token}` }).expect(404);
});

test('project invitations, live notifications, and AI generation work', async () => {
  await db.initialize();
  const owner = await request(app).post('/api/auth/register').send({
    name: 'Project Owner', email: 'owner@example.com', password: 'owner-password-123',
  }).expect(201);
  const invitee = await request(app).post('/api/auth/register').send({
    name: 'Invited Member', email: 'invitee@example.com', password: 'invitee-password-123',
  }).expect(201);
  const ownerAuth = { Authorization: `Bearer ${owner.body.token}` };
  const inviteeAuth = { Authorization: `Bearer ${invitee.body.token}` };
  const project = await request(app).post('/api/projects').set(ownerAuth)
    .send({ name: 'Collaboration project' }).expect(201);
  const invitationResponse = await request(app).post(`/api/projects/${project.body.project.id}/invitations`)
    .set(ownerAuth).send({ email: 'invitee@example.com' }).expect(201);
  const invitationToken = invitationResponse.body.invitation.token;

  await request(app).post('/api/invitations/accept').set(ownerAuth)
    .send({ token: invitationToken }).expect(403);
  await request(app).post('/api/invitations/accept').set(inviteeAuth)
    .send({ token: invitationToken }).expect(200);
  await request(app).post('/api/invitations/accept').set(inviteeAuth)
    .send({ token: invitationToken }).expect(404);
  await request(app).get(`/api/projects/${project.body.project.id}/members`).set(inviteeAuth)
    .expect(200);
  const pendingInvitation = await request(app).post(`/api/projects/${project.body.project.id}/invitations`)
    .set(ownerAuth).send({ email: 'pending@example.com' }).expect(201);
  await request(app).get(`/api/projects/${project.body.project.id}/invitations`).set(ownerAuth).expect(200);
  await request(app).delete(`/api/projects/${project.body.project.id}/invitations/${pendingInvitation.body.invitation.id}`)
    .set(ownerAuth).expect(204);

  const server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  const address = server.address();
  const stream = await fetch(`http://127.0.0.1:${address.port}/api/notifications/stream`, {
    headers: { Authorization: `Bearer ${invitee.body.token}` },
  });
  assert.equal(stream.status, 200);
  const reader = stream.body.getReader();
  const decoder = new TextDecoder();
  try {
    const ready = await reader.read();
    assert.match(decoder.decode(ready.value), /event: ready/);
    const task = await request(app).post('/api/tasks').set(ownerAuth).send({
      projectId: project.body.project.id,
      title: 'Review the release',
      assigneeId: invitee.body.user.id,
    }).expect(201);
    const liveUpdate = await reader.read();
    assert.match(decoder.decode(liveUpdate.value), /event: notification/);
    const notifications = await request(app).get('/api/notifications?unreadOnly=true')
      .set(inviteeAuth).expect(200);
    const assigned = notifications.body.notifications.find((item) => item.type === 'task_assigned');
    assert.ok(assigned);
    assert.equal(assigned.taskId, task.body.task.id);
    await request(app).patch(`/api/notifications/${assigned.id}/read`).set(inviteeAuth).expect(204);
    const unread = await request(app).get('/api/notifications?unreadOnly=true').set(inviteeAuth).expect(200);
    assert.equal(unread.body.notifications.length, 0);
    await request(app).patch(`/api/tasks/${task.body.task.id}`).set(ownerAuth)
      .send({ status: 'in_progress' }).expect(200);
    const updatedNotifications = await request(app).get('/api/notifications?unreadOnly=true')
      .set(inviteeAuth).expect(200);
    assert.ok(updatedNotifications.body.notifications.some((item) => item.type === 'task_updated'));
    await request(app).post('/api/notifications/read-all').set(inviteeAuth).expect(204);
  } finally {
    await reader.cancel();
    await new Promise((resolve) => server.close(resolve));
  }

  const originalFetch = global.fetch;
  const originalApiKey = process.env.AI_API_KEY;
  const originalBaseUrl = process.env.AI_BASE_URL;
  const originalModel = process.env.AI_MODEL;
  let aiRequest;
  process.env.AI_API_KEY = 'test-ai-key';
  process.env.AI_BASE_URL = 'https://ai.example/v1/';
  process.env.AI_MODEL = 'test-model';
  global.fetch = async (url, options) => {
    aiRequest = { url, options };
    return new Response(JSON.stringify({
      choices: [{ message: { content: 'A generated, actionable task description.' } }],
    }), { status: 200 });
  };
  try {
    const generated = await request(app).post('/api/ai/generate').set(ownerAuth).send({
      kind: 'description', title: 'Review the release', context: 'Check deployment readiness.',
    }).expect(200);
    assert.equal(generated.body.text, 'A generated, actionable task description.');
    assert.equal(generated.body.model, 'test-model');
    assert.equal(aiRequest.url, 'https://ai.example/v1/chat/completions');
    assert.equal(aiRequest.options.headers.Authorization, 'Bearer test-ai-key');
    const summary = await request(app).post('/api/ai/generate').set(ownerAuth).send({
      kind: 'summary', text: 'Task one is open. Task two is complete.',
    }).expect(200);
    assert.equal(summary.body.kind, 'summary');
  } finally {
    global.fetch = originalFetch;
    if (originalApiKey === undefined) delete process.env.AI_API_KEY;
    else process.env.AI_API_KEY = originalApiKey;
    if (originalBaseUrl === undefined) delete process.env.AI_BASE_URL;
    else process.env.AI_BASE_URL = originalBaseUrl;
    if (originalModel === undefined) delete process.env.AI_MODEL;
    else process.env.AI_MODEL = originalModel;
  }

  const configuredApiKey = process.env.AI_API_KEY;
  delete process.env.AI_API_KEY;
  try {
    await request(app).post('/api/ai/generate').set(ownerAuth).send({
      kind: 'summary', text: 'AI is not configured in this test request.',
    }).expect(503);
  } finally {
    if (configuredApiKey !== undefined) process.env.AI_API_KEY = configuredApiKey;
  }
});
