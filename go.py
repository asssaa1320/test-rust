#!/usr/bin/env python3
"""
Chromium Semantic HTML Fuzzer
Target: Blink rendering engine, V8 JS engine, CSS engine
Goal: Discover memory corruption bugs (UAF, OOB, Double-Free, etc.)
Usage: python3 fuzzer.py [--chromium /path/to/chrome] [--timeout 10] [--output ./corpus]
"""

import os
import sys
import time
import random
import string
import subprocess
import argparse
import json
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional

# ──────────────────────────────────────────────
# MUTATION BUILDING BLOCKS
# ──────────────────────────────────────────────

CSS_PROPERTIES = [
    "display:contents", "display:grid", "display:flow-root",
    "contain:strict", "contain:layout paint",
    "will-change:transform", "will-change:opacity,filter",
    "isolation:isolate",
    "transform:translateZ(0) scale(0)",
    "clip-path:polygon(0 0,100% 0,100% 100%)",
    "shape-outside:circle(50%)",
    "content-visibility:auto",
    "overflow:clip",
    "position:sticky", "position:fixed",
    "backface-visibility:hidden",
    "perspective:1px",
    "filter:blur(0px)",
    "mix-blend-mode:multiply",
    "forced-color-adjust:none",
    "column-count:2", "column-span:all",
    "grid-template-columns:subgrid",
    "masonry-auto-flow:pack",         # experimental
    "writing-mode:vertical-rl",
    "direction:rtl",
    "ruby-align:center",
    "text-combine-upright:all",
    "scroll-snap-type:both mandatory",
    "overscroll-behavior:contain",
    "touch-action:none",
    "pointer-events:none",
    "resize:both",
    "appearance:none",
    "user-select:all",
    "box-decoration-break:clone",
    "paint-order:stroke markers fill",
]

HTML_TAGS = [
    "div", "span", "p", "table", "tr", "td", "th", "thead", "tbody", "tfoot",
    "form", "input", "select", "option", "textarea", "button", "label",
    "details", "summary", "dialog", "slot", "template",
    "svg", "canvas", "video", "audio", "picture", "source",
    "ruby", "rt", "rp", "rb",
    "math", "mrow", "mfrac", "msup", "msub",
    "iframe", "object", "embed",
    "fieldset", "legend",
    "ul", "ol", "li", "dl", "dt", "dd",
    "figure", "figcaption", "article", "section", "aside", "nav", "header", "footer",
    "h1","h2","h3","h4","h5","h6",
    "blockquote", "cite", "pre", "code", "kbd", "samp", "var",
    "ins", "del", "mark", "s", "u", "small", "sub", "sup",
    "a", "area", "map",
    "track", "col", "colgroup", "caption",
    "portal",   # experimental
    "fencedframe",  # experimental
]

EVENTS = [
    "onload","onerror","onclick","ondblclick","onmousedown","onmouseup",
    "onmousemove","onmouseenter","onmouseleave","onmouseover","onmouseout",
    "onkeydown","onkeyup","onkeypress",
    "onfocus","onblur","onchange","oninput","onsubmit","onreset",
    "ondragstart","ondrag","ondragend","ondragenter","ondragleave","ondrop",
    "ontouchstart","ontouchmove","ontouchend","ontouchcancel",
    "onpointerdown","onpointermove","onpointerup","onpointercancel","onpointerenter","onpointerleave",
    "onanimationstart","onanimationend","onanimationiteration",
    "ontransitionstart","ontransitionend","ontransitioncancel",
    "onscroll","onresize","onselect","oncontextmenu",
    "onwheel","onpaste","oncopy","oncut",
    "onfullscreenchange","onfullscreenerror",
    "onslotchange",
    "oncuechange",
    "onmessage","onmessageerror",
    "onclose","onopen",
    "onbeforeinput",
    "onsecuritypolicyviolation",
]

JS_SNIPPETS = [
    # DOM manipulation
    "el.remove(); el.remove();",                             # double remove → UAF
    "el.parentNode && el.parentNode.removeChild(el);",
    "document.adoptNode(el);",
    "document.importNode(el, true);",
    "el.replaceWith(el);",                                   # self-replace
    "el.append(el);",                                        # self-append → cycle
    "el.before(el);",
    "el.after(el);",
    "el.prepend(el);",

    # Shadow DOM
    "el.attachShadow({mode:'open'}).appendChild(el.cloneNode(true));",
    "el.attachShadow({mode:'closed'});",

    # Layout triggers
    "void el.offsetWidth; el.style.display='none'; void el.offsetWidth;",
    "el.getBoundingClientRect(); el.remove(); el.getBoundingClientRect();",
    "getComputedStyle(el).getPropertyValue('--x');",

    # Attribute mutation
    "el.setAttribute('style','display:contents'); el.removeAttribute('style');",
    "el.className = 'a b c'; el.className = '';",
    "el.id = 'x'; document.getElementById('x').remove();",

    # Dynamic CSS
    "document.styleSheets[0] && document.styleSheets[0].deleteRule(0);",
    "let s=document.createElement('style'); s.textContent='*{display:none}'; document.head.appendChild(s); s.remove();",

    # Canvas / WebGL
    "let c=document.createElement('canvas'); let g=c.getContext('webgl'); g && g.getExtension('WEBGL_lose_context') && g.getExtension('WEBGL_lose_context').loseContext();",
    "let c2=document.createElement('canvas'); let x=c2.getContext('2d'); x.drawImage(c2,0,0);",  # draw self

    # Workers / SAB
    "new Worker(URL.createObjectURL(new Blob(['postMessage(1)'],{type:'text/javascript'}))).terminate();",

    # Intersection / Resize / Mutation observer
    "new IntersectionObserver(()=>{}).observe(el); el.remove();",
    "new ResizeObserver(()=>{}).observe(el); el.style.width='100px';",
    "new MutationObserver(m=>{m.forEach(r=>r.removedNodes.forEach(n=>n.remove()))}).observe(el,{childList:true}); el.innerHTML='<b/>';",

    # History / Navigation
    "history.pushState(null,'',location.href); history.back();",

    # Form
    "document.forms[0] && document.forms[0].requestSubmit();",

    # Selection / Range
    "let r=document.createRange(); r.selectNodeContents(el); r.deleteContents(); r.detach();",
    "getSelection().selectAllChildren(el); getSelection().deleteFromDocument();",

    # CSSOM
    "let ss=new CSSStyleSheet(); ss.replaceSync('div{color:red}'); document.adoptedStyleSheets=[ss];",
    "document.adoptedStyleSheets=[];",

    # Async / microtask storm
    "Promise.resolve().then(()=>el.remove()).then(()=>el.remove());",
    "queueMicrotask(()=>{el.style.display='grid'; queueMicrotask(()=>el.remove());});",

    # requestAnimationFrame chain
    "let i=0; function f(){if(i++<5){el.style.opacity=i%2; requestAnimationFrame(f);}} requestAnimationFrame(f);",

    # Scroll-snap
    "el.scrollIntoView({behavior:'smooth'}); el.remove();",

    # XHR/Fetch abort
    "let ac=new AbortController(); fetch('/',{signal:ac.signal}).catch(()=>{}); ac.abort();",

    # Audio / Video
    "let v=document.createElement('video'); v.src='data:,'; document.body.appendChild(v); v.play().catch(()=>{}); v.remove();",

    # CSS Animations via JS
    "el.animate([{opacity:0},{opacity:1}],{duration:100,iterations:Infinity}).cancel();",

    # WeakRef / FinalizationRegistry
    "let wr=new WeakRef(el); el.remove(); el=null; wr.deref();",
    "let fr=new FinalizationRegistry(()=>{}); fr.register(el,'x');",
]

ATTRIBUTE_MUTATIONS = [
    ('contenteditable', ['true', 'false', 'plaintext-only', '']),
    ('tabindex', ['-1', '0', '1', '32767']),
    ('draggable', ['true', 'false', 'auto']),
    ('hidden', ['', 'until-found']),
    ('inert', ['']),
    ('part', ['foo bar']),
    ('exportparts', ['foo']),
    ('slot', ['s1']),
    ('is', ['x-custom']),
    ('popover', ['', 'auto', 'manual']),
    ('popovertarget', ['target']),
    ('invoketarget', ['target']),  # experimental
    ('anchor', ['anchor-el']),     # CSS anchor positioning
    ('spellcheck', ['true', 'false']),
    ('autocorrect', ['on', 'off']),
    ('translate', ['yes', 'no']),
    ('dir', ['ltr', 'rtl', 'auto']),
    ('lang', ['ar', 'en-US', 'zh-Hant']),
    ('autocapitalize', ['on', 'off', 'words', 'sentences', 'characters']),
    ('inputmode', ['none', 'text', 'decimal', 'numeric', 'tel', 'search', 'email', 'url']),
    ('enterkeyhint', ['enter', 'done', 'go', 'next', 'previous', 'search', 'send']),
    ('virtualkeyboardpolicy', ['auto', 'manual']),
]


# ──────────────────────────────────────────────
# HTML TEMPLATE GENERATORS
# ──────────────────────────────────────────────

def rand_id(n=6):
    return ''.join(random.choices(string.ascii_lowercase, k=n))

def rand_css():
    props = random.sample(CSS_PROPERTIES, k=random.randint(1, 4))
    return '; '.join(props)

def rand_attrs():
    chosen = random.sample(ATTRIBUTE_MUTATIONS, k=random.randint(0, 3))
    parts = []
    for attr, vals in chosen:
        parts.append(f'{attr}="{random.choice(vals)}"')
    return ' '.join(parts)

def rand_event(var='el'):
    snippet = random.choice(JS_SNIPPETS).replace('el', var)
    ev = random.choice(EVENTS)
    return f'{ev}="try{{{snippet}}}catch(e){{}}"'

def build_dom_tree(depth=3, tag_id='root') -> str:
    if depth == 0:
        return f'<span id="{rand_id()}" style="{rand_css()}">text</span>'
    tag = random.choice(HTML_TAGS[:20])   # stick to safe structural tags for nesting
    eid = rand_id()
    children = ''.join(build_dom_tree(depth-1) for _ in range(random.randint(1,3)))
    attrs = rand_attrs()
    ev = rand_event(f'document.getElementById("{eid}")')
    return f'<{tag} id="{eid}" style="{rand_css()}" {attrs} {ev}>{children}</{tag}>'


def gen_shadow_dom_section() -> str:
    hid = rand_id()
    return f"""
<div id="{hid}">
  <template shadowrootmode="open">
    <style> :host {{ display: block; {rand_css()} }} </style>
    <slot></slot>
    <div style="{rand_css()}">shadow content</div>
  </template>
  <span>light dom child</span>
</div>"""


def gen_css_animations() -> str:
    name = rand_id()
    prop = random.choice(['opacity','transform','color','width','height','clip-path','filter'])
    return f"""
<style>
@keyframes {name} {{
  0%   {{ {prop}: initial }}
  50%  {{ {prop}: inherit }}
  100% {{ {prop}: unset }}
}}
.anim-{name} {{ animation: {name} 0.1s infinite alternate; {rand_css()} }}
</style>
<div class="anim-{name}" style="{rand_css()}">{build_dom_tree(1)}</div>"""


def gen_table_section() -> str:
    rows = random.randint(2, 5)
    cols = random.randint(2, 5)
    cells = ''
    for r in range(rows):
        cells += '<tr>'
        for c in range(cols):
            tag = random.choice(['td','th'])
            rs = random.randint(1,2)
            cs = random.randint(1,2)
            cells += f'<{tag} rowspan="{rs}" colspan="{cs}" style="{rand_css()}">{r},{c}</{tag}>'
        cells += '</tr>'
    return f"""
<table style="{rand_css()}">
  <colgroup><col style="{rand_css()}"><col span="2" style="{rand_css()}"></colgroup>
  <caption style="{rand_css()}">table caption</caption>
  <thead>{cells}</thead>
  <tbody>{cells}</tbody>
  <tfoot>{cells}</tfoot>
</table>"""


def gen_svg_section() -> str:
    sid = rand_id()
    return f"""
<svg id="{sid}" width="200" height="200" xmlns="http://www.w3.org/2000/svg"
     style="{rand_css()}" {rand_event(f'document.getElementById("{sid}")')}>
  <defs>
    <filter id="f-{sid}">
      <feTurbulence baseFrequency="0.05" numOctaves="3"/>
      <feDisplacementMap in="SourceGraphic" scale="20"/>
    </filter>
    <clipPath id="cp-{sid}"><rect width="100" height="100"/></clipPath>
    <marker id="m-{sid}" markerWidth="10" markerHeight="10" refX="5" refY="5">
      <circle cx="5" cy="5" r="5"/>
    </marker>
  </defs>
  <rect width="200" height="200" filter="url(#f-{sid})" clip-path="url(#cp-{sid})"/>
  <path d="M10 10 Q 90 90 180 10" marker-end="url(#m-{sid})" stroke="black" fill="none"/>
  <foreignObject width="100" height="100">
    <div xmlns="http://www.w3.org/1999/xhtml" style="{rand_css()}">fo content</div>
  </foreignObject>
</svg>"""


def gen_canvas_webgl_section() -> str:
    cid = rand_id()
    return f"""
<canvas id="{cid}" width="256" height="256"></canvas>
<script>
(function(){{
  var c = document.getElementById('{cid}');
  var gl = c.getContext('webgl2') || c.getContext('webgl');
  if (!gl) return;
  var vert = gl.createShader(gl.VERTEX_SHADER);
  gl.shaderSource(vert, 'void main(){{gl_Position=vec4(0,0,0,1);gl_PointSize=1.0;}}');
  gl.compileShader(vert);
  var frag = gl.createShader(gl.FRAGMENT_SHADER);
  gl.shaderSource(frag, 'precision mediump float; void main(){{gl_FragColor=vec4(1,0,0,1);}}');
  gl.compileShader(frag);
  var prog = gl.createProgram();
  gl.attachShader(prog, vert);
  gl.attachShader(prog, frag);
  gl.linkProgram(prog);
  gl.useProgram(prog);
  var buf = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, buf);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([0,0,0]), gl.DYNAMIC_DRAW);
  gl.drawArrays(gl.POINTS, 0, 1);
  // trigger context loss
  var ext = gl.getExtension('WEBGL_lose_context');
  if (ext) {{ setTimeout(()=>ext.loseContext(), {random.randint(10,200)}); }}
  // delete resources while in flight
  setTimeout(()=>{{ gl.deleteBuffer(buf); gl.deleteProgram(prog); }}, {random.randint(5,100)});
}})();
</script>"""


def gen_iframe_section() -> str:
    content = f"<html><body style='{rand_css()}'><script>parent.postMessage('ping','*');</scr" + "ipt></body></html>"
    encoded = content.replace('"', '&quot;')
    return f"""
<iframe id="fr-{rand_id()}"
        srcdoc="{encoded}"
        sandbox="allow-scripts allow-same-origin"
        style="{rand_css()}"
        loading="lazy"
        onload="try{{this.contentDocument.body.style.cssText='{rand_css()}'}}catch(e){{}}">
</iframe>"""


def gen_js_uaf_patterns() -> str:
    """JavaScript patterns that stress lifecycle and GC boundaries."""
    eid = rand_id()
    delay1 = random.randint(0, 50)
    delay2 = random.randint(0, 50)
    snippet = random.choice(JS_SNIPPETS)
    return f"""
<script>
(function() {{
  'use strict';
  var el = document.getElementById('{eid}') || document.body.firstElementChild;
  if (!el) return;

  // ── pattern 1: observer + removal
  var mo = new MutationObserver(function(mutations) {{
    mutations.forEach(function(m) {{
      m.removedNodes.forEach(function(n) {{
        try {{ n.parentNode && n.parentNode.removeChild(n); }} catch(e) {{}}
      }});
    }});
  }});
  mo.observe(el.parentNode || document.body, {{childList: true, subtree: true}});

  // ── pattern 2: async remove + style access
  var clone = el.cloneNode(true);
  document.body.appendChild(clone);
  var timer1 = setTimeout(function() {{
    try {{
      clone.remove();
      void clone.offsetHeight;   // UAF bait after remove
    }} catch(e) {{}}
  }}, {delay1});

  // ── pattern 3: JS snippet from mutation lib
  try {{ {snippet} }} catch(e) {{}}

  // ── pattern 4: layout thrash → GC pressure
  var arr = [];
  for (var i = 0; i < 500; i++) {{
    var d = document.createElement('div');
    d.style.cssText = 'display:contents;contain:strict';
    document.body.appendChild(d);
    arr.push(d);
  }}
  arr.forEach(function(d) {{ d.remove(); }});
  arr = null;

  // ── pattern 5: rAF chain with style mutation
  var raf_count = 0;
  function rafLoop() {{
    if (raf_count++ > 20) return;
    try {{
      el.style.display = raf_count % 2 === 0 ? 'none' : 'block';
      void el.getBoundingClientRect();
    }} catch(e) {{}}
    requestAnimationFrame(rafLoop);
  }}
  requestAnimationFrame(rafLoop);

  // cleanup
  setTimeout(function() {{
    clearTimeout(timer1);
    mo.disconnect();
  }}, 500);
}})();
</script>"""


def gen_custom_elements_section() -> str:
    cname = 'x-' + rand_id()
    return f"""
<script>
(function() {{
  if (customElements.get('{cname}')) return;
  class El extends HTMLElement {{
    constructor() {{ super(); this.attachShadow({{mode:'open'}}); }}
    connectedCallback() {{
      this.shadowRoot.innerHTML = '<style>:host{{display:block;{rand_css()}}}</style><slot></slot>';
      requestAnimationFrame(() => {{
        try {{ this.remove(); void this.isConnected; }} catch(e) {{}}
      }});
    }}
    disconnectedCallback() {{
      try {{ this.shadowRoot.innerHTML = ''; }} catch(e) {{}}
    }}
    attributeChangedCallback(n, o, v) {{
      try {{ this.style.cssText = v; }} catch(e) {{}}
    }}
    static get observedAttributes() {{ return ['data-style']; }}
  }}
  customElements.define('{cname}', El);
}})();
</script>
<{cname} data-style="{rand_css()}" style="{rand_css()}">
  <span slot="s">child</span>
</{cname}>"""


def gen_css_houdini_section() -> str:
    name = rand_id()
    return f"""
<script>
if (window.CSS && CSS.registerProperty) {{
  try {{
    CSS.registerProperty({{
      name: '--{name}',
      syntax: '<color>',
      inherits: true,
      initialValue: 'red'
    }});
  }} catch(e) {{}}
}}
if (window.CSS && CSS.paintWorklet) {{
  try {{
    CSS.paintWorklet.addModule(URL.createObjectURL(new Blob([
      'registerPaint("p-{name}", class {{ paint(ctx, size) {{ ctx.fillRect(0,0,size.width,size.height); }} }})'
    ], {{type:'text/javascript'}})));
  }} catch(e) {{}}
}}
</script>
<div style="--{name}: blue; background: paint(p-{name}); {rand_css()}">houdini test</div>"""


# ──────────────────────────────────────────────
# FULL HTML DOCUMENT ASSEMBLER
# ──────────────────────────────────────────────

def generate_html(seed: int, prev_crash_hints: list = None) -> str:
    random.seed(seed)
    doc_id = rand_id()

    # Choose which sections to include (vary per seed)
    sections = []

    sections.append(gen_css_animations())
    sections.append(build_dom_tree(depth=random.randint(2,4)))
    sections.append(gen_shadow_dom_section())
    sections.append(gen_table_section())

    if random.random() > 0.3:
        sections.append(gen_svg_section())
    if random.random() > 0.4:
        sections.append(gen_canvas_webgl_section())
    if random.random() > 0.5:
        sections.append(gen_iframe_section())
    if random.random() > 0.3:
        sections.append(gen_custom_elements_section())
    if random.random() > 0.6:
        sections.append(gen_css_houdini_section())

    random.shuffle(sections)

    # Pick a target element id from the DOM
    eid = rand_id()
    uaf_js = gen_js_uaf_patterns()

    # Crash-hint guided extra mutations
    extra_hints = ''
    if prev_crash_hints:
        for hint in prev_crash_hints[:3]:
            if 'LayoutObject' in hint or 'layout' in hint.lower():
                extra_hints += f'\n<div style="contain:strict;display:contents;overflow:clip;{rand_css()}"><div style="{rand_css()}">layout stress</div></div>'
            if 'v8' in hint.lower() or 'js' in hint.lower():
                extra_hints += '\n<script>try{(new Array(1e6)).fill(0).map((v,i)=>i*i);}catch(e){}</script>'
            if 'paint' in hint.lower() or 'composit' in hint.lower():
                extra_hints += f'\n<div style="will-change:transform;backface-visibility:hidden;filter:blur(0px);{rand_css()}">compositor target</div>'
            if 'audio' in hint.lower() or 'media' in hint.lower():
                extra_hints += '\n<video src="data:," autoplay muted playsinline style="display:none"></video>'

    html = f"""<!DOCTYPE html>
<html lang="en" dir="{random.choice(['ltr','rtl'])}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>fuzz-{seed}</title>
<style>
/* Base stress styles */
*, *::before, *::after {{
  box-sizing: border-box;
  {random.choice(CSS_PROPERTIES)};
}}
:root {{
  --primary: red;
  --secondary: blue;
  contain: {random.choice(['none','content','strict','layout'])};
}}
body {{
  {rand_css()};
  overflow: {random.choice(['visible','hidden','clip','scroll','auto'])};
}}
/* CSS counter stress */
body {{ counter-reset: c1 c2 c3; }}
div::before {{ counter-increment: c1; content: counter(c1) ' / ' counters(c2, '.'); }}
/* CSS grid / flex stress */
.grid-host {{
  display: {random.choice(['grid','flex','inline-grid','inline-flex'])};
  grid-template-columns: repeat(auto-fill, minmax(50px,1fr));
  gap: 4px;
  {rand_css()};
}}
/* Containment */
.contain-me {{
  contain: layout paint style;
  content-visibility: auto;
  {rand_css()};
}}
</style>
</head>
<body id="{doc_id}">

<!-- ═══ SEMANTIC MUTATION SECTIONS ═══ -->
{''.join(f"<!-- section {i+1} -->{s}" for i,s in enumerate(sections))}

<!-- ═══ CRASH-HINT EXTRA MUTATIONS ═══ -->
{extra_hints}

<!-- ═══ UAF / LIFECYCLE STRESS PATTERNS ═══ -->
<div id="{eid}" class="contain-me grid-host" style="{rand_css()}">
  {build_dom_tree(depth=2)}
</div>

{uaf_js}

<!-- ═══ GLOBAL STRESS SCRIPT ═══ -->
<script>
(function() {{
  'use strict';
  // ── Rapid DOM churn
  function churn(root, depth) {{
    if (depth <= 0) return;
    var tags = ['div','span','p','details','dialog'];
    var child = document.createElement(tags[depth % tags.length]);
    child.style.cssText = '{rand_css()}';
    root.appendChild(child);
    churn(child, depth - 1);
    setTimeout(function() {{
      try {{ child.remove(); churn(root, depth); }} catch(e) {{}}
    }}, {random.randint(10, 100)});
  }}
  churn(document.body, 5);

  // ── Adopted stylesheets stress
  var sheets = [];
  for (var i = 0; i < 10; i++) {{
    try {{
      var s = new CSSStyleSheet();
      s.replaceSync('div:nth-child(' + i + '){{color:hsl(' + (i*36) + ',100%,50%)}}');
      sheets.push(s);
    }} catch(e) {{}}
  }}
  document.adoptedStyleSheets = sheets;
  setTimeout(function() {{ document.adoptedStyleSheets = []; }}, 300);

  // ── Selection / Range stress
  try {{
    var sel = window.getSelection();
    var rng = document.createRange();
    rng.selectNodeContents(document.body);
    sel.addRange(rng);
    setTimeout(function() {{
      try {{ sel.deleteFromDocument(); }} catch(e) {{}}
      try {{ rng.detach(); }} catch(e) {{}}
    }}, 150);
  }} catch(e) {{}}

  // ── Intersection observer flood
  var io = new IntersectionObserver(function() {{}});
  document.querySelectorAll('*').forEach(function(el) {{ try {{ io.observe(el); }} catch(e) {{}} }});
  setTimeout(function() {{ io.disconnect(); }}, 200);

  // ── Force GC candidate
  (function() {{
    var objs = [];
    for (var i = 0; i < 2000; i++) {{
      var d = document.createElement('div');
      d.setAttribute('data-x', i);
      objs.push(d);
    }}
    objs = null;  // eligible for GC without ever being attached
  }})();

}})();
</script>

</body>
</html>
"""
    return html


# ──────────────────────────────────────────────
# CRASH LOG ANALYZER
# ──────────────────────────────────────────────

def analyze_crash(log_text: str) -> dict:
    """
    Parse ASan / crash log and extract hints for next mutation.
    Returns a dict with category, frames, and hints list.
    """
    result = {
        'category': 'UNKNOWN',
        'frames': [],
        'hints': [],
        'severity': 'LOW',
    }

    # Detect crash type
    if 'heap-use-after-free' in log_text:
        result['category'] = 'HEAP_UAF'
        result['severity'] = 'CRITICAL'
        result['hints'].append('UAF detected — increase removal timing jitter')
        result['hints'].append('LayoutObject')
    elif 'heap-buffer-overflow' in log_text:
        result['category'] = 'HEAP_OVERFLOW'
        result['severity'] = 'CRITICAL'
        result['hints'].append('Overflow — try extreme attribute values, large strings')
    elif 'stack-buffer-overflow' in log_text:
        result['category'] = 'STACK_OVERFLOW'
        result['severity'] = 'HIGH'
        result['hints'].append('Stack — try deeply nested DOM trees')
    elif 'double-free' in log_text:
        result['category'] = 'DOUBLE_FREE'
        result['severity'] = 'CRITICAL'
        result['hints'].append('Double-free — add more double-remove patterns')
    elif 'use-of-uninitialized-value' in log_text or 'MSan' in log_text:
        result['category'] = 'UNINIT_MEM'
        result['severity'] = 'HIGH'
        result['hints'].append('MSan — focus on uninitialized reads in new codepaths')
    elif 'out-of-bounds' in log_text or 'SEGV' in log_text:
        result['category'] = 'OOB'
        result['severity'] = 'HIGH'
        result['hints'].append('OOB — stress array indices, typed arrays, canvas pixel ops')

    # Extract stack frames (ASan format: #N 0xADDR in FunctionName file.cc:line)
    import re
    frames = re.findall(r'#\d+\s+0x[0-9a-f]+\s+in\s+(\S+)', log_text)
    result['frames'] = frames[:10]

    # Generate semantic hints from frame names
    for frame in frames[:5]:
        fl = frame.lower()
        if 'layout' in fl or 'layoutobject' in fl:
            result['hints'].append('layout')
        if 'paint' in fl or 'compositor' in fl:
            result['hints'].append('paint')
        if 'v8' in fl or 'builtins' in fl or 'runtime' in fl:
            result['hints'].append('v8')
        if 'audio' in fl or 'media' in fl or 'webmedia' in fl:
            result['hints'].append('audio')
        if 'css' in fl or 'style' in fl or 'computed' in fl:
            result['hints'].append('css')
        if 'shadow' in fl or 'slot' in fl:
            result['hints'].append('shadow')
        if 'canvas' in fl or 'webgl' in fl or 'gpu' in fl:
            result['hints'].append('canvas')
        if 'selection' in fl or 'range' in fl:
            result['hints'].append('selection')

    result['hints'] = list(dict.fromkeys(result['hints']))  # deduplicate
    return result


# ──────────────────────────────────────────────
# RUNNER
# ──────────────────────────────────────────────

def run_chromium(chromium_bin: str, html_path: str, timeout: int, asan_log_dir: str) -> Optional[str]:
    """
    Launch Chromium with ASan-friendly flags.
    Returns crash log path if crash detected, else None.
    """
    log_prefix = os.path.join(asan_log_dir, f'asan_{os.path.basename(html_path)}')

    env = os.environ.copy()
    env['ASAN_OPTIONS'] = (
        'halt_on_error=1:'
        'abort_on_error=1:'
        'detect_leaks=0:'          # disable LSan during fuzzing for speed
        'symbolize=1:'
        f'log_path={log_prefix}:'
        'redzone=128:'
        'max_malloc_fill_size=4096:'
        'allow_user_segv_handler=0'
    )
    env['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'

    cmd = [
        chromium_bin,
        '--no-sandbox',
        '--disable-gpu-sandbox',
        '--disable-setuid-sandbox',
        '--single-process',          # easier to catch crashes; remove for realism
        '--disable-extensions',
        '--disable-background-networking',
        '--disable-default-apps',
        '--disable-sync',
        '--no-first-run',
        '--headless=new',
        '--disable-dev-shm-usage',
        '--js-flags=--expose-gc',    # allow gc() calls from JS
        '--enable-features=WebAssemblyBaseline',
        f'file://{os.path.abspath(html_path)}'
    ]

    try:
        proc = subprocess.run(
            cmd,
            timeout=timeout,
            capture_output=True,
            env=env
        )
        # Check for ASan log files
        for f in Path(asan_log_dir).glob(f'asan_{os.path.basename(html_path)}.*'):
            if f.stat().st_size > 100:
                return str(f)
        # Non-zero exit can also mean crash
        if proc.returncode not in (0, -15):  # -15 = SIGTERM (timeout)
            # write stderr as crash log
            crash_path = f'{log_prefix}.stderr'
            Path(crash_path).write_bytes(proc.stderr)
            if proc.stderr:
                return crash_path
    except subprocess.TimeoutExpired:
        pass
    except FileNotFoundError:
        print(f'[ERROR] Chromium not found at: {chromium_bin}')
        sys.exit(1)

    return None


# ──────────────────────────────────────────────
# MAIN FEEDBACK LOOP
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Chromium Semantic HTML Fuzzer')
    parser.add_argument('--chromium', default='/usr/bin/chromium',
                        help='Path to ASan-instrumented Chromium binary')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Seconds to wait per test case')
    parser.add_argument('--output', default='./corpus',
                        help='Directory for HTML corpus and crash logs')
    parser.add_argument('--iterations', type=int, default=100,
                        help='Number of fuzz iterations')
    parser.add_argument('--seed', type=int, default=None,
                        help='Starting random seed (default: time-based)')
    parser.add_argument('--dry-run', action='store_true',
                        help='Generate HTML only, do not launch Chromium')
    args = parser.parse_args()

    # Setup directories
    corpus_dir = Path(args.output) / 'html'
    crash_dir  = Path(args.output) / 'crashes'
    asan_dir   = Path(args.output) / 'asan_logs'
    for d in [corpus_dir, crash_dir, asan_dir]:
        d.mkdir(parents=True, exist_ok=True)

    seed = args.seed if args.seed is not None else int(time.time())
    crash_hints: list = []
    crash_count = 0
    results_log = []

    print(f"""
╔══════════════════════════════════════════════════════╗
║        Chromium Semantic HTML Fuzzer                 ║
║  Target  : Blink / V8 / CSS engine                  ║
║  Strategy: Semantic mutations + feedback loop        ║
╚══════════════════════════════════════════════════════╝
  Chromium : {args.chromium}
  Output   : {args.output}
  Seed     : {seed}
  Iterations: {args.iterations}
  Dry-run  : {args.dry_run}
─────────────────────────────────────────────────────
""")

    for i in range(args.iterations):
        current_seed = seed + i
        ts = datetime.now().strftime('%H:%M:%S')
        html_name = f'fuzz_{current_seed:08d}.html'
        html_path = corpus_dir / html_name

        # Generate
        html_content = generate_html(current_seed, crash_hints)
        html_path.write_text(html_content, encoding='utf-8')

        print(f'[{ts}] [{i+1:4d}/{args.iterations}] seed={current_seed}  file={html_name}', end='  ')

        if args.dry_run:
            print('(dry-run — HTML written, skipping Chromium)')
            continue

        # Run
        crash_log = run_chromium(args.chromium, str(html_path), args.timeout, str(asan_dir))

        if crash_log:
            crash_count += 1
            log_text = Path(crash_log).read_text(errors='replace')
            analysis = analyze_crash(log_text)
            crash_hints = analysis['hints']

            # Copy crash artifacts
            crash_html = crash_dir / html_name
            html_path.rename(crash_html)
            crash_info = crash_dir / f'fuzz_{current_seed:08d}_analysis.json'
            crash_info.write_text(json.dumps({
                'seed': current_seed,
                'html': str(crash_html),
                'asan_log': crash_log,
                'analysis': analysis,
            }, indent=2))

            print(f'💥 CRASH [{analysis["severity"]}] {analysis["category"]}')
            print(f'         frames: {" → ".join(analysis["frames"][:4])}')
            print(f'         next hints: {crash_hints}')
            print(f'         saved to: {crash_html}')
        else:
            crash_hints = []  # reset hints after clean run
            print('✓ clean')

        results_log.append({
            'seed': current_seed,
            'html': html_name,
            'crash': crash_log is not None,
        })

    # Summary
    summary_path = Path(args.output) / 'summary.json'
    summary_path.write_text(json.dumps({
        'total': args.iterations,
        'crashes': crash_count,
        'results': results_log,
    }, indent=2))

    print(f"""
─────────────────────────────────────────────────────
  Done. {crash_count} crash(es) found in {args.iterations} iterations.
  Results: {summary_path}
  Crashes: {crash_dir}
─────────────────────────────────────────────────────
""")


if __name__ == '__main__':
    main()