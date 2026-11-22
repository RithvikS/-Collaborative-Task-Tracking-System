const { EventEmitter } = require('node:events');

const events = new EventEmitter();
events.setMaxListeners(0);

function publishNotification(userId, notification) {
  events.emit(userId, notification);
}

function subscribeToNotifications(userId, listener) {
  events.on(userId, listener);
  return () => events.off(userId, listener);
}

module.exports = { publishNotification, subscribeToNotifications };
