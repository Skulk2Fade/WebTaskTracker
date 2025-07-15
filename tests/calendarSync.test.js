const https = require('https');
const { EventEmitter } = require('events');

let calls;

function mockRequest(opts, callback) {
  const req = new EventEmitter();
  req.body = '';
  req.write = chunk => { req.body += chunk; };
  req.end = () => {
    calls.push({ opts, body: req.body });
    const res = new EventEmitter();
    callback(res);
    process.nextTick(() => {
      if (opts.method === 'DELETE') {
        res.emit('end');
        return;
      }
      const id = opts.hostname === 'www.googleapis.com' ? 'g123' : 'o456';
      res.emit('data', Buffer.from(JSON.stringify({ id })));
      res.emit('end');
    });
  };
  req.on = jest.fn();
  return req;
}

describe('calendar sync', () => {
  beforeEach(() => {
    calls = [];
    jest.resetModules();
    jest.spyOn(https, 'request').mockImplementation(mockRequest);
    process.env.GOOGLE_SYNC_TOKEN = 'gtoken';
    process.env.GOOGLE_CALENDAR_ID = 'gcal';
    process.env.OUTLOOK_SYNC_TOKEN = 'otoken';
    process.env.OUTLOOK_CALENDAR_ID = 'ocal';
  });

  afterEach(() => {
    https.request.mockRestore();
  });

  test('syncTask and deleteTask interact with calendars', async () => {
    const { syncTask, deleteTask } = require('../calendarSync');

    const task = {
      id: 1,
      text: 'Test',
      dueDate: '2099-12-31',
      dueTime: '12:00'
    };

    await syncTask(task); // create
    task.text = 'Updated';
    await syncTask(task); // update
    await deleteTask(task.id); // remove

    expect(calls.length).toBe(6);

    // first call creates Google event
    expect(calls[0].opts.hostname).toBe('www.googleapis.com');
    expect(calls[0].opts.method).toBe('POST');
    // second call creates Outlook event
    expect(calls[1].opts.hostname).toBe('graph.microsoft.com');
    expect(calls[1].opts.method).toBe('POST');

    // third call updates Google event
    expect(calls[2].opts.method).toBe('PATCH');
    expect(calls[2].opts.path).toContain('/events/g123');
    // fourth call updates Outlook event
    expect(calls[3].opts.method).toBe('PATCH');
    expect(calls[3].opts.path).toContain('/events/o456');

    // delete calls
    expect(calls[4].opts.method).toBe('DELETE');
    expect(calls[4].opts.path).toContain('/events/g123');
    expect(calls[5].opts.method).toBe('DELETE');
    expect(calls[5].opts.path).toContain('/events/o456');
  });
});
