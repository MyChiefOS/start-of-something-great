// The 23 rooms (the design handoff of Nov 5, 2026, README "Rooms"): the major groups of the US Standard Occupational
// Classification, 2018 edition, by code, in the design's short names. Public data, not sample figures. Read by
// room.js and projects.js; rooms.html and projects.html carry the same list in their HTML (test/design-modules-b.test.js
// keeps them in step), so those pages show it with no script.
(function () {
  'use strict';
  window.DOG_ROOMS = [
    ['11-0000', 'Management'],
    ['13-0000', 'Business & Financial Operations'],
    ['15-0000', 'Computer & Mathematical'],
    ['17-0000', 'Architecture & Engineering'],
    ['19-0000', 'Life, Physical & Social Science'],
    ['21-0000', 'Community & Social Service'],
    ['23-0000', 'Legal'],
    ['25-0000', 'Educational Instruction & Library'],
    ['27-0000', 'Arts, Design, Entertainment, Sports & Media'],
    ['29-0000', 'Healthcare Practitioners & Technical'],
    ['31-0000', 'Healthcare Support'],
    ['33-0000', 'Protective Service'],
    ['35-0000', 'Food Preparation & Serving'],
    ['37-0000', 'Building & Grounds Cleaning & Maintenance'],
    ['39-0000', 'Personal Care & Service'],
    ['41-0000', 'Sales & Related'],
    ['43-0000', 'Office & Administrative Support'],
    ['45-0000', 'Farming, Fishing & Forestry'],
    ['47-0000', 'Construction & Extraction'],
    ['49-0000', 'Installation, Maintenance & Repair'],
    ['51-0000', 'Production'],
    ['53-0000', 'Transportation & Material Moving'],
    ['55-0000', 'Military Specific']
  ];
})();
