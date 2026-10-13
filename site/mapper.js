// Address → name mapper for the landing page (shared by EN and DE).
// Mirrors PanoptiDNS' rule in the browser: the host part of the address,
// as lowercase hex zero-padded to (128 - prefixlen) / 4 digits, is
// substituted for %DIGITS% (or %DIGITS-DASHED%, grouped in 4s). Messages
// come from data-msg-* attributes on #mapper so the script stays language-neutral.
(function () {
  var root = document.getElementById("mapper");
  if (!root) return;
  var addrIn = root.querySelector("[name=addr]");
  var netIn = root.querySelector("[name=net]");
  var tplIn = root.querySelector("[name=tpl]");
  var out = {
    ptr: root.querySelector("[data-out=ptr]"),
    name: root.querySelector("[data-out=name]"),
    aaaa: root.querySelector("[data-out=aaaa]"),
  };
  function msg(k) { return root.getAttribute("data-msg-" + k) || k; }

  function parse6(s) {
    s = s.trim().toLowerCase();
    if (!/^[0-9a-f:]+$/.test(s) || s.indexOf(":::") >= 0) return null;
    var halves = s.split("::");
    if (halves.length > 2) return null;
    var head = halves[0] ? halves[0].split(":") : [];
    var tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
    var missing = 8 - head.length - tail.length;
    if (halves.length === 1 ? missing !== 0 : missing < 1) return null;
    var groups = head.concat(new Array(halves.length === 2 ? missing : 0).fill("0"), tail);
    var v = 0n;
    for (var i = 0; i < 8; i++) {
      if (!/^[0-9a-f]{1,4}$/.test(groups[i])) return null;
      v = (v << 16n) | BigInt(parseInt(groups[i], 16));
    }
    return v;
  }
  function hex32(v) { return v.toString(16).padStart(32, "0"); }
  function fmt6(v) {
    var h = hex32(v), g = [];
    for (var i = 0; i < 32; i += 4) g.push(h.slice(i, i + 4).replace(/^0+(?=.)/, ""));
    // compress the longest run of zero groups
    var best = -1, len = 0;
    for (var s = 0; s < 8; s++) {
      var e = s; while (e < 8 && g[e] === "0") e++;
      if (e - s > len && e - s > 1) { best = s; len = e - s; }
    }
    if (best < 0) return g.join(":");
    return g.slice(0, best).join(":") + "::" + g.slice(best + len).join(":");
  }
  function esc(s) {
    return s.replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; });
  }
  function row(el, html, err) {
    el.innerHTML = html;
    el.parentElement.classList.toggle("is-err", !!err);
  }

  function update() {
    var addr = parse6(addrIn.value);
    var m = /^\s*([0-9a-fA-F:]+)\/(\d{1,3})\s*$/.exec(netIn.value);
    var net = m && parse6(m[1]);
    var plen = m ? parseInt(m[2], 10) : -1;
    if (addr === null) {
      row(out.ptr, esc(msg("invalid")), true); row(out.name, "—"); row(out.aaaa, "—");
      return;
    }
    var h = hex32(addr);
    var ptr = h.split("").reverse().join(".") + ".ip6.arpa.";
    if (net === null || plen < 0 || plen > 124 || plen % 4 !== 0) {
      row(out.ptr, esc(ptr));
      row(out.name, esc(msg("prefix")), true); row(out.aaaa, "—");
      return;
    }
    var mask = plen === 0 ? 0n : ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - plen)) - 1n);
    var hostDigits = (128 - plen) / 4;
    var hostStart = 32 - hostDigits;
    // highlight the host-part nibbles in the PTR name (they come first, reversed)
    var labels = h.split("").reverse();
    var ptrHtml = labels.map(function (c, i) { return i < hostDigits ? "<b>" + c + "</b>" : c; }).join(".") + ".ip6.arpa.";
    if ((addr & mask) !== (net & mask)) {
      row(out.ptr, ptrHtml);
      row(out.name, esc(msg("outside")), true); row(out.aaaa, "—");
      return;
    }
    var digits = h.slice(hostStart);
    var tpl = tplIn.value;
    if (tpl.indexOf("%DIGITS-DASHED%") >= 0) {
      if (plen % 16 !== 0) {
        row(out.ptr, ptrHtml); row(out.name, esc(msg("dashed")), true); row(out.aaaa, "—");
        return;
      }
      var dashed = digits.match(/.{1,4}/g).join("-");
      tpl = tpl.replace("%DIGITS-DASHED%", "\u0000" + dashed + "\u0001");
    } else {
      tpl = tpl.replace("%DIGITS%", "\u0000" + digits + "\u0001");
    }
    var nameHtml = esc(tpl).replace("\u0000", "<b>").replace("\u0001", "</b>") + ".";
    row(out.ptr, ptrHtml);
    row(out.name, nameHtml);
    row(out.aaaa, esc(fmt6(addr)));
  }

  [addrIn, netIn, tplIn].forEach(function (el) {
    el.addEventListener("input", update);
    el.addEventListener("change", update);
  });
  update();
})();
