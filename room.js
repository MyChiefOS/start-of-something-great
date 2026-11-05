// /rooms/{code} (the design handoff of Nov 5, 2026, static/room.html): one room, named from its code in the address
// (vercel.json sends /rooms/<code> here). The names are the 23 SOC 2018 major groups (soc-rooms.js). The chips switch
// between this room's leaderboard and the overall one; both are empty until projects are built (phase 5). Text only.
(function () {
  'use strict';
  var rooms = window.DOG_ROOMS || [];
  var name = document.getElementById('room-name');
  var crumb = document.getElementById('room-crumb');
  var dekCode = document.getElementById('room-dek-code');
  var found = document.getElementById('room-found');
  var missing = document.getElementById('room-missing');
  var missingText = document.getElementById('room-missing-text');
  var chips = document.getElementById('board-chips');
  var boardRoom = document.getElementById('board-room');
  var boardOverall = document.getElementById('board-overall');
  var boardTitle = document.getElementById('board-title');

  var m = /^\/rooms\/([0-9]{2}-0000)\/?$/.exec(location.pathname);
  var code = m ? m[1] : null;
  var room = null;
  for (var i = 0; i < rooms.length; i++) if (rooms[i][0] === code) room = rooms[i];

  if (!room) {
    found.hidden = true;
    missing.hidden = false;
    name.textContent = 'Room not found';
    crumb.textContent = 'Not found';
    document.getElementById('room-dek').hidden = true;
    if (code) missingText.textContent = 'There is no room with the code ' + code + '.';
    document.title = 'Room not found: Day One Great';
    return;
  }

  name.textContent = room[1];
  crumb.textContent = room[0];
  dekCode.textContent = 'Room ' + room[0] + '. ';
  document.title = room[1] + ': Day One Great';

  function show(board) {
    boardRoom.hidden = board !== 'room';
    boardOverall.hidden = board !== 'overall';
    boardTitle.textContent = board === 'room' ? 'Specialist leaderboard' : 'Overall leaderboard';
    Array.prototype.forEach.call(chips.querySelectorAll('button[data-board]'), function (b) {
      b.setAttribute('aria-pressed', String(b.getAttribute('data-board') === board));
    });
  }
  chips.addEventListener('click', function (ev) {
    var b = ev.target.closest('button[data-board]');
    if (b) show(b.getAttribute('data-board'));
  });
  chips.hidden = false;
})();
