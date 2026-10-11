// Public status-page traffic sparkline. External file so the nonce-only CSP allows it.
(function(){
  var canvas = document.getElementById('spark');
  if (!canvas) return;
  var values;
  try { values = JSON.parse(canvas.getAttribute('data-values') || '[]'); } catch (e) { return; }
  if (!values.length) return;
  var ctx = canvas.getContext('2d');
  var w = canvas.offsetWidth || 560, h = canvas.offsetHeight || 80;
  canvas.width = w; canvas.height = h;
  var max = Math.max.apply(null, values) || 1;
  var step = w / ((values.length - 1) || 1);
  ctx.strokeStyle = 'rgb(180,140,60)'; ctx.lineWidth = 2; ctx.beginPath();
  values.forEach(function(v, i) {
    var x = i * step, y = h - (v / max) * (h - 8) - 4;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.stroke();
})();
