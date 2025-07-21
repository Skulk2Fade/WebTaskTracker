/**
 * @fileoverview Common JSDoc type definitions used across the project.
 * This module exports nothing and only exists for documentation and editor
 * tooling support.
 */

/* eslint-disable no-unused-vars */

/**
 * Recurrence rule for monthly repeating tasks.
 * @typedef {Object} RecurrenceRule
 * @property {number} weekday - Day of week (0-6, Sun-Sat)
 * @property {number} ordinal - Ordinal occurrence within the month (1-5)
 */

/**
 * A task item stored in the database.
 * @typedef {Object} Task
 * @property {number} id
 * @property {string} text
 * @property {string} [dueDate]
 * @property {string} [dueTime]
 * @property {'high'|'medium'|'low'} priority
 * @property {string} status
 * @property {boolean} done
 * @property {number} [userId]
 * @property {string} [category]
 * @property {string[]} [tags]
 * @property {number} [assignedTo]
 * @property {number} [groupId]
 * @property {string} [repeatInterval]
 * @property {RecurrenceRule} [recurrenceRule]
 * @property {boolean} reminderSent
 * @property {string|null} lastReminderDate
 */

/**
 * A subtask belonging to a parent task.
 * @typedef {Object} Subtask
 * @property {number} id
 * @property {number} taskId
 * @property {string} text
 * @property {boolean} done
 */

/**
 * Comment left on a task by a user.
 * @typedef {Object} Comment
 * @property {number} id
 * @property {number} taskId
 * @property {number} userId
 * @property {string} text
 * @property {string} createdAt
 * @property {string} username
 */

/**
 * File or binary attachment associated with a task or comment.
 * @typedef {Object} Attachment
 * @property {number} id
 * @property {number} [taskId]
 * @property {number} [commentId]
 * @property {string} filename
 * @property {string} mimeType
 * @property {Buffer} [data]
 * @property {string} [filePath]
 */

module.exports = {};
