/* The browser only filters existing paths: a removed edge blocks its entire path. */
(function () {
  'use strict';
  const report = JSON.parse(document.getElementById('report-data').textContent);
  const toggles = Array.from(document.querySelectorAll('.fix-toggle'));
  const nodeKeys = new Map(report.graph.nodes.map((n, i) => [n.id, 'node-' + i]));
  const edgeKeys = new Map(report.graph.edges.map((e, i) => [e.id, 'edge-' + i]));
  const cy = cytoscape({container: document.getElementById('attack-graph'),
    elements: [
      ...report.graph.nodes.map(n => ({data: {id: nodeKeys.get(n.id), label: n.id}})),
      ...report.graph.edges.map(e => ({data: {id: edgeKeys.get(e.id), source: nodeKeys.get(e.src), target: nodeKeys.get(e.dst)}}))
    ],
    style: [
      {selector: 'node', style: {'background-color': '#14685b', label: 'data(label)', 'font-size': 11, 'text-valign': 'bottom', 'text-margin-y': 8}},
      {selector: 'edge', style: {'line-color': '#9aafb9', 'target-arrow-color': '#9aafb9', 'target-arrow-shape': 'triangle', 'curve-style': 'bezier', width: 2}},
      {selector: '.blocked', style: {'line-color': '#d6dce0', 'target-arrow-color': '#d6dce0', 'line-style': 'dashed', opacity: .35}}
    ], layout: {name: 'breadthfirst', directed: true, padding: 40}});
  new ResizeObserver(() => { cy.resize(); cy.fit(undefined, 40); }).observe(document.getElementById('attack-graph'));
  function update() {
    const blocked = new Set();
    toggles.forEach(box => {
      if (box.checked) report.fix_candidates[Number(box.dataset.fixIndex)].breaks_edges.forEach(e => blocked.add(e));
    });
    const remaining = report.paths.filter(p => !p.edges.some(e => blocked.has(e)));
    document.getElementById('what-if-summary').textContent = `${remaining.length} of ${report.paths.length} paths remain.`;
    const list = document.getElementById('what-if-paths');
    list.replaceChildren();
    remaining.forEach(p => { const li = document.createElement('li'); li.textContent = `${p.id}: ${p.entry} → ${p.goal} (${p.band}, ${p.confidence.toFixed(3)})`; list.appendChild(li); });
    report.graph.edges.forEach(e => cy.getElementById(edgeKeys.get(e.id)).toggleClass('blocked', blocked.has(e.id)));
  }
  toggles.forEach(box => box.addEventListener('change', update));
  document.getElementById('select-recommended').addEventListener('click', () => {
    toggles.forEach(box => { box.checked = report.fix_sets.greedy.includes(report.fix_candidates[Number(box.dataset.fixIndex)].id); }); update();
  });
  document.getElementById('clear-fixes').addEventListener('click', () => { toggles.forEach(box => { box.checked = false; }); update(); });
  update();
}());
