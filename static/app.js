const KINDS = [
  ["page", "Seite", "#b7c0c8"],
  ["asset", "Datei", "#8d867c"],
  ["probe", "Exploit", "#9a9286"],
  ["ssh", "SSH", "#c45c3e"],
  ["scan", "Scan", "#6d8ea3"],
  ["flood", "Flut", "#c4894a"],
  ["login", "Login", "#a86b52"],
  ["mail", "Mail", "#7d9a6a"],
  ["self", "Self", "#7aa0b8"],
];
const KIND = Object.fromEntries(KINDS.map(([id, label, color]) => [id, { label, color }]));
const ROLES = [
  ["all", "Alles"],
  ["traffic", "Verkehr"],
  ["burst", "Auffällig"],
  ["botnet", "Botnetz"],
  ["org", "Netze"],
];
const ATTACKS = new Set(["ssh", "scan", "flood", "login", "mail", "probe"]);
const BAN_KINDS = new Set(["ssh", "scan", "flood", "login", "mail"]);
const THREAT = {
  ssh: 1, flood: 0.95, scan: 0.85, login: 0.8, mail: 0.75, probe: 0.7,
  page: 0.15, asset: 0.08, self: 0.12,
};
const SPEEDS = [
  [1, "1×"],
  [30, "30×"],
  [120, "2 Min/s"],
  [600, "10 Min/s"],
];
const WINDOWS = [
  [5 * 60, "5 Min"],
  [30 * 60, "30 Min"],
  [2 * 3600, "2 Std"],
  [12 * 3600, "12 Std"],
];

const LIVE_SPAN = 2 * 60;

const state = {
  server: { lat: 52.52, lon: 13.405, city: "Berlin", name: "Infynnite" },
  events: [],
  hits: [],
  role: "all",
  picked: null,
  waveZoom: 1,
  waveOrigin: null,
  features: [],
  cursor: 0,
  windowSec: 30 * 60,
  speed: 30,
  follow: true,
  playing: false,
  filters: new Set(KINDS.map(([id]) => id)),
  domain: "",
  onlyBanned: false,
  bans: new Map(),
  banRev: 0,
  selected: null,
  born: new Map(),
  lastFrame: performance.now(),
  actions: false,
  jails: ["sshd", "nginx-404-flood", "nginx-env-scan", "nginx-http-auth"],
  lookup: null,
  lookupIp: "",
  link: "boot",
  query: "",
  selfIp: "",
  stars: [],
};

const canvas = document.getElementById("map");
const ctx = canvas.getContext("2d");
const wave = document.getElementById("wave");
const wctx = wave.getContext("2d");
const feed = document.getElementById("feed");
const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
let waveBins = [];
let waveKey = "";

function flagSrc(cc) {
  return /^[A-Za-z]{2}$/.test(cc || "") ? `/flags/${cc.toLowerCase()}.svg` : "";
}

function isSelf(row) {
  return !!(row && state.selfIp && row.ip === state.selfIp);
}

function viewKind(row) {
  return isSelf(row) ? "self" : row && row.kind;
}

function arcColor(ev) {
  if (isSelf(ev)) return "#7aa0b8";
  return (KIND[ev.kind] || KIND.probe).color;
}

function markSrc(row) {
  if (isSelf(row)) return "/marks/self.svg";
  if (row.role === "org" && row.org) return `/marks/${row.org}.svg`;
  if (row.role === "burst" || row.org === "burst") return "/marks/burst.svg";
  if (row.role === "botnet") return "/marks/botnet.svg";
  return "/marks/globe.svg";
}

const WINDOWS_NAMES = {
  "10.0": "Windows",
  "6.3": "Windows 8.1",
  "6.2": "Windows 8",
  "6.1": "Windows 7",
  "6.0": "Windows Vista",
  "5.2": "Windows Server",
  "5.1": "Windows XP",
};

const IOT_RULES = [
  [/hikvision|dahua|reolink|amcrest|foscam|vivotek|onvif|dvrdvs|xmeye|netwave|webLanguage|device\.rsp|\/SDK\//i, "IoT · Kamera"],
  [/tasmota|esp8266|esp32|esphome|shelly|sonoff|\btuya\b|smartlife|ewelink|homeassistant|home assistant/i, "IoT · Steuerung"],
  [/boaform|gponform|HNAP1|\/goform\/|setup\.cgi|cgi-bin\/luci|mikrotik|openwrt|ubiquiti|\bubnt\b|edgeos|fritz!|picsdesc\.xml|tmUnblock/i, "IoT · Router"],
  [/goahead-webs|micro_httpd|busybox|lwip\/|appweb\//i, "IoT · Gerät"],
];

function detectOs(ua) {
  const text = String(ua || "");
  if (!text || text === "-") return null;
  let match = text.match(/OS (\d+)[_.]\d+/);
  if (/iPhone|iPad|iPod/.test(text)) {
    return { icon: "/marks/apple.svg", label: match ? `iOS ${match[1]}` : "iOS" };
  }
  match = text.match(/Android (\d+(?:\.\d+)?)/);
  if (/Android/.test(text)) {
    return { icon: "/marks/os-android.svg", label: match ? `Android ${match[1]}` : "Android" };
  }
  if (/CrOS/.test(text)) return { icon: "/marks/os-linux.svg", label: "ChromeOS" };
  match = text.match(/Windows NT ([\d.]+)/);
  if (match || /Windows/.test(text)) {
    return { icon: "/marks/microsoft.svg", label: WINDOWS_NAMES[match && match[1]] || "Windows" };
  }
  if (/Macintosh|Mac OS X/.test(text)) return { icon: "/marks/apple.svg", label: "macOS" };
  if (/Linux|X11/.test(text)) return { icon: "/marks/os-linux.svg", label: "Linux" };
  return null;
}

function detectIot(ua, path) {
  const text = `${ua || ""} ${path || ""}`;
  for (const [pattern, label] of IOT_RULES) {
    if (pattern.test(text)) return { icon: "/marks/os-iot.svg", label };
  }
  return null;
}

function clientMarks(row) {
  const marks = [];
  const os = detectOs(row && row.ua);
  const iot = detectIot(row && row.ua, row && row.path);
  if (os) marks.push(os);
  if (iot && (!os || iot.label !== os.label)) marks.push(iot);
  return marks;
}

function osLine(marks) {
  if (!marks.length) return null;
  const line = document.createElement("span");
  line.className = "os-line";
  marks.forEach((part, index) => {
    if (index) line.append(document.createTextNode(" · "));
    const img = document.createElement("img");
    img.className = "mark";
    img.alt = "";
    img.src = part.icon;
    line.append(img, document.createTextNode(part.label));
  });
  return line;
}

function setLabeled(node, name, cc) {
  node.replaceChildren();
  const src = flagSrc(cc);
  if (src) {
    const img = document.createElement("img");
    img.className = "flag";
    img.alt = "";
    img.src = src;
    node.append(img);
  }
  node.append(document.createTextNode(name || "Unbekannt"));
}

function formatTime(ts) {
  const d = new Date(ts * 1000);
  return new Intl.DateTimeFormat("de-DE", {
    timeZone: "Europe/Berlin",
    day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
  }).format(d);
}

function paintHeaderClock() {
  const now = new Date();
  const dateEl = document.getElementById("headerDate");
  const timeEl = document.getElementById("headerTime");
  if (dateEl) {
    const parts = new Intl.DateTimeFormat("de-DE", {
      timeZone: "Europe/Berlin",
      weekday: "short", day: "2-digit", month: "2-digit", year: "numeric",
    }).formatToParts(now);
    const part = (type) => parts.find((item) => item.type === type)?.value || "";
    const weekday = part("weekday");
    dateEl.textContent = `${weekday.endsWith(".") ? weekday : `${weekday}.`}, ${part("day")}.${part("month")}.`;
    const yearEl = document.getElementById("headerYear");
    if (yearEl) yearEl.textContent = part("year");
  }
  if (timeEl) {
    timeEl.textContent = new Intl.DateTimeFormat("de-DE", {
      timeZone: "Europe/Berlin",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    }).format(now);
  }
}

const GEO = {
  Afghanistan: ["AF", "Afghanistan"], Angola: ["AO", "Angola"], Albania: ["AL", "Albanien"],
  "United Arab Emirates": ["AE", "Vereinigte Arabische Emirate"], Argentina: ["AR", "Argentinien"],
  Armenia: ["AM", "Armenien"], Australia: ["AU", "Australien"], Austria: ["AT", "Österreich"],
  Azerbaijan: ["AZ", "Aserbaidschan"], Burundi: ["BI", "Burundi"], Belgium: ["BE", "Belgien"],
  Benin: ["BJ", "Benin"], "Burkina Faso": ["BF", "Burkina Faso"], Bangladesh: ["BD", "Bangladesch"],
  Bulgaria: ["BG", "Bulgarien"], "The Bahamas": ["BS", "Bahamas"], "Bosnia and Herzegovina": ["BA", "Bosnien und Herzegowina"],
  Belarus: ["BY", "Belarus"], Belize: ["BZ", "Belize"], Bolivia: ["BO", "Bolivien"], Brazil: ["BR", "Brasilien"],
  Brunei: ["BN", "Brunei"], Bhutan: ["BT", "Bhutan"], Botswana: ["BW", "Botsuana"],
  "Central African Republic": ["CF", "Zentralafrika"], Canada: ["CA", "Kanada"], Switzerland: ["CH", "Schweiz"],
  Chile: ["CL", "Chile"], China: ["CN", "China"], "Ivory Coast": ["CI", "Côte d'Ivoire"], Cameroon: ["CM", "Kamerun"],
  "Democratic Republic of the Congo": ["CD", "Kongo (DR)"], "Republic of the Congo": ["CG", "Kongo"],
  Colombia: ["CO", "Kolumbien"], "Costa Rica": ["CR", "Costa Rica"], Cuba: ["CU", "Kuba"], Cyprus: ["CY", "Zypern"],
  "Czech Republic": ["CZ", "Tschechien"], Germany: ["DE", "Deutschland"], Djibouti: ["DJ", "Dschibuti"],
  Denmark: ["DK", "Dänemark"], "Dominican Republic": ["DO", "Dominikanische Republik"], Algeria: ["DZ", "Algerien"],
  Ecuador: ["EC", "Ecuador"], Egypt: ["EG", "Ägypten"], Eritrea: ["ER", "Eritrea"], Spain: ["ES", "Spanien"],
  Estonia: ["EE", "Estland"], Ethiopia: ["ET", "Äthiopien"], Finland: ["FI", "Finnland"], France: ["FR", "Frankreich"],
  Gabon: ["GA", "Gabun"], England: ["GB", "England"], Georgia: ["GE", "Georgien"], Ghana: ["GH", "Ghana"],
  Greece: ["GR", "Griechenland"], Greenland: ["GL", "Grönland"], Guatemala: ["GT", "Guatemala"],
  Honduras: ["HN", "Honduras"], Croatia: ["HR", "Kroatien"], Haiti: ["HT", "Haiti"], Hungary: ["HU", "Ungarn"],
  Indonesia: ["ID", "Indonesien"], India: ["IN", "Indien"], Ireland: ["IE", "Irland"], Iran: ["IR", "Iran"],
  Iraq: ["IQ", "Irak"], Iceland: ["IS", "Island"], Israel: ["IL", "Israel"], Italy: ["IT", "Italien"],
  Jamaica: ["JM", "Jamaika"], Jordan: ["JO", "Jordanien"], Japan: ["JP", "Japan"], Kazakhstan: ["KZ", "Kasachstan"],
  Kenya: ["KE", "Kenia"], Kyrgyzstan: ["KG", "Kirgisistan"], Cambodia: ["KH", "Kambodscha"],
  "South Korea": ["KR", "Südkorea"], Kosovo: ["XK", "Kosovo"], Kuwait: ["KW", "Kuwait"], Laos: ["LA", "Laos"],
  Lebanon: ["LB", "Libanon"], Liberia: ["LR", "Liberia"], Libya: ["LY", "Libyen"], "Sri Lanka": ["LK", "Sri Lanka"],
  Lesotho: ["LS", "Lesotho"], Lithuania: ["LT", "Litauen"], Luxembourg: ["LU", "Luxemburg"], Latvia: ["LV", "Lettland"],
  Morocco: ["MA", "Marokko"], Moldova: ["MD", "Moldau"], Madagascar: ["MG", "Madagaskar"], Mexico: ["MX", "Mexiko"],
  Macedonia: ["MK", "Nordmazedonien"], Mali: ["ML", "Mali"], Myanmar: ["MM", "Myanmar"], Montenegro: ["ME", "Montenegro"],
  Mongolia: ["MN", "Mongolei"], Mozambique: ["MZ", "Mosambik"], Mauritania: ["MR", "Mauretanien"], Malawi: ["MW", "Malawi"],
  Malaysia: ["MY", "Malaysia"], Namibia: ["NA", "Namibia"], Niger: ["NE", "Niger"], Nigeria: ["NG", "Nigeria"],
  Nicaragua: ["NI", "Nicaragua"], Netherlands: ["NL", "Niederlande"], Norway: ["NO", "Norwegen"], Nepal: ["NP", "Nepal"],
  "New Zealand": ["NZ", "Neuseeland"], Oman: ["OM", "Oman"], Pakistan: ["PK", "Pakistan"], Panama: ["PA", "Panama"],
  Peru: ["PE", "Peru"], Philippines: ["PH", "Philippinen"], "Papua New Guinea": ["PG", "Papua-Neuguinea"],
  Poland: ["PL", "Polen"], "Puerto Rico": ["PR", "Puerto Rico"], "North Korea": ["KP", "Nordkorea"],
  Portugal: ["PT", "Portugal"], Paraguay: ["PY", "Paraguay"], Qatar: ["QA", "Katar"], Romania: ["RO", "Rumänien"],
  Russia: ["RU", "Russland"], Rwanda: ["RW", "Ruanda"], "Saudi Arabia": ["SA", "Saudi-Arabien"], Sudan: ["SD", "Sudan"],
  Senegal: ["SN", "Senegal"], "El Salvador": ["SV", "El Salvador"], Somalia: ["SO", "Somalia"],
  "Republic of Serbia": ["RS", "Serbien"], Suriname: ["SR", "Suriname"], Slovakia: ["SK", "Slowakei"],
  Slovenia: ["SI", "Slowenien"], Sweden: ["SE", "Schweden"], Swaziland: ["SZ", "Eswatini"], Syria: ["SY", "Syrien"],
  Chad: ["TD", "Tschad"], Togo: ["TG", "Togo"], Thailand: ["TH", "Thailand"], Tajikistan: ["TJ", "Tadschikistan"],
  Turkmenistan: ["TM", "Turkmenistan"], "East Timor": ["TL", "Osttimor"], "Trinidad and Tobago": ["TT", "Trinidad und Tobago"],
  Tunisia: ["TN", "Tunesien"], Turkey: ["TR", "Türkei"], Taiwan: ["TW", "Taiwan"],
  "United Republic of Tanzania": ["TZ", "Tansania"], Uganda: ["UG", "Uganda"], Ukraine: ["UA", "Ukraine"],
  Uruguay: ["UY", "Uruguay"], USA: ["US", "USA"], Uzbekistan: ["UZ", "Usbekistan"], Venezuela: ["VE", "Venezuela"],
  Vietnam: ["VN", "Vietnam"], "West Bank": ["PS", "Westjordanland"], Yemen: ["YE", "Jemen"],
  "South Africa": ["ZA", "Südafrika"], Zambia: ["ZM", "Sambia"], Zimbabwe: ["ZW", "Simbabwe"],
};

const cam = { lon: 0, lat: 0, scale: 1 };
const camTarget = { lon: 0, lat: 0, scale: 1 };
const MIN_SCALE = 1;
const MAX_SCALE = 32;
let mapBox = { x: 0, y: 0, w: 1, h: 1 };
let hoverItem = null;
let focusItem = null;

function project(lon, lat, box) {
  const wx = (lon + 180) / 360;
  const wy = (90 - lat) / 180;
  const cx = (cam.lon + 180) / 360;
  const cy = (90 - cam.lat) / 180;
  return [
    box.x + box.w / 2 + (wx - cx) * box.w * cam.scale,
    box.y + box.h / 2 + (wy - cy) * box.h * cam.scale,
  ];
}

function unproject(x, y, box) {
  const wx = (x - box.x - box.w / 2) / (box.w * cam.scale) + (cam.lon + 180) / 360;
  const wy = (y - box.y - box.h / 2) / (box.h * cam.scale) + (90 - cam.lat) / 180;
  return [wx * 360 - 180, 90 - wy * 180];
}

let camAnim = null;

function shortestLon(from, to) {
  let delta = to - from;
  if (delta > 180) delta -= 360;
  if (delta < -180) delta += 360;
  return from + delta;
}

function clampCam(lon, lat, scale) {
  return {
    lon: ((lon + 540) % 360) - 180,
    lat: Math.max(-80, Math.min(80, lat)),
    scale: Math.min(MAX_SCALE, Math.max(MIN_SCALE, scale)),
  };
}

function setCam(lon, lat, scale) {
  const next = clampCam(lon, lat, scale);
  camAnim = null;
  cam.lon = next.lon;
  cam.lat = next.lat;
  cam.scale = next.scale;
  camTarget.lon = next.lon;
  camTarget.lat = next.lat;
  camTarget.scale = next.scale;
}

function moveCam(lon, lat, scale, dur = 680) {
  const next = clampCam(lon, lat, scale);
  camTarget.lon = next.lon;
  camTarget.lat = next.lat;
  camTarget.scale = next.scale;
  camAnim = {
    fromLon: cam.lon,
    toLon: shortestLon(cam.lon, next.lon),
    fromLat: cam.lat,
    toLat: next.lat,
    fromScale: Math.log(Math.max(0.2, cam.scale)),
    toScale: Math.log(Math.max(0.2, next.scale)),
    t0: performance.now(),
    dur: reduced ? 0 : dur,
  };
}

function easeCam(now) {
  if (!camAnim) return;
  const t = camAnim.dur <= 0 ? 1 : Math.min(1, (now - camAnim.t0) / camAnim.dur);
  const s = t < 0.5 ? 4 * t * t * t : 1 - ((-2 * t + 2) ** 3) / 2;
  cam.lon = camAnim.fromLon + (camAnim.toLon - camAnim.fromLon) * s;
  cam.lat = camAnim.fromLat + (camAnim.toLat - camAnim.fromLat) * s;
  cam.scale = Math.exp(camAnim.fromScale + (camAnim.toScale - camAnim.fromScale) * s);
  if (t >= 1) {
    cam.lon = camTarget.lon;
    cam.lat = camTarget.lat;
    cam.scale = camTarget.scale;
    camAnim = null;
  }
}

function viewBox() {
  const w = canvas.width;
  const h = canvas.height;
  const ratio = 2;
  const pad = 8;
  let bw = w - pad * 2;
  let bh = bw / ratio;
  if (bh > h - pad * 2) {
    bh = h - pad * 2;
    bw = bh * ratio;
  }
  return { x: (w - bw) / 2, y: (h - bh) / 2, w: bw, h: bh };
}

let viewW = 0;
let viewH = 0;

function resize() {
  const rect = canvas.getBoundingClientRect();
  const dpr = Math.min(2, devicePixelRatio || 1);
  const width = Math.max(1, Math.floor(rect.width * dpr));
  const height = Math.max(1, Math.floor(rect.height * dpr));
  if (width === viewW && height === viewH) return;
  viewW = width;
  viewH = height;
  canvas.width = width;
  canvas.height = height;
  mapLayerKey = "";
  heatStamp = 0;
}

function traceGeometry(geometry, box, context = ctx) {
  const polys = geometry.type === "Polygon" ? [geometry.coordinates] : geometry.coordinates;
  for (const poly of polys) {
    for (const ring of poly) {
      let open = false;
      let prev = null;
      for (const [lon, lat] of ring) {
        if (prev && Math.abs(lon - prev[0]) > 180) {
          if (open) context.closePath();
          open = false;
        }
        const [x, y] = project(lon, lat, box);
        if (!open) {
          context.moveTo(x, y);
          open = true;
        } else context.lineTo(x, y);
        prev = [lon, lat];
      }
      if (open) context.closePath();
    }
  }
}

let mapLayer = null;
let mapLayerKey = "";
let mapPose = null;
let mapBuiltAt = 0;

function cameraShifted(pose) {
  if (!pose) return true;
  let dLon = pose.lon - cam.lon;
  if (dLon > 180) dLon -= 360;
  if (dLon < -180) dLon += 360;
  const dScale = Math.abs(pose.scale - cam.scale) / Math.max(pose.scale, 0.001);
  return Math.abs(dLon) > 0.004 || Math.abs(pose.lat - cam.lat) > 0.004 || dScale > 0.012;
}

function blitLayer(layer, box, pose) {
  let dLon = pose.lon - cam.lon;
  if (dLon > 180) dLon -= 360;
  if (dLon < -180) dLon += 360;
  const k = cam.scale / Math.max(0.2, pose.scale);
  const dx = (dLon / 360) * box.w * cam.scale;
  const dy = ((cam.lat - pose.lat) / 180) * box.h * cam.scale;
  const cx = box.x + box.w / 2;
  const cy = box.y + box.h / 2;
  const origin = pose.overscan || 1;
  ctx.save();
  ctx.imageSmoothingEnabled = true;
  ctx.imageSmoothingQuality = "high";
  ctx.translate(cx + dx, cy + dy);
  ctx.scale(k, k);
  ctx.translate(-cx * origin, -cy * origin);
  ctx.drawImage(layer, 0, 0);
  ctx.restore();
}

const MAP_OVERSCAN = 2;

function poseStale(pose, overscan = 1) {
  if (!pose) return true;
  const k = cam.scale / Math.max(0.2, pose.scale);
  const cover = overscan * 0.82;
  if (k > 1.35 || k * cover < 1) return true;
  let dLon = pose.lon - cam.lon;
  if (dLon > 180) dLon -= 360;
  if (dLon < -180) dLon += 360;
  const margin = Math.max(0.12, (overscan - 1) * 0.34);
  const panX = Math.abs(dLon) * pose.scale / 360;
  const panY = Math.abs(cam.lat - pose.lat) * pose.scale / 180;
  return panX > margin || panY > margin;
}

function themePaint() {
  const light = document.documentElement.dataset.theme === "light";
  if (light) {
    return {
      sea: "#e7edf2",
      land: "#c5d0da",
      edge: "#aebcc8",
      ink: "#1c2126",
      grid: "rgba(90, 104, 118, 0.28)",
      stroke: "rgba(70, 84, 98, 0.4)",
      flash: "#4c5966",
    };
  }
  return {
    sea: "#0b0e11",
    land: "#3a4450",
    edge: "#4a5664",
    ink: "#d8dde3",
    grid: "rgba(122, 137, 152, 0.2)",
    stroke: "rgba(152, 167, 182, 0.34)",
    flash: "#c5d0db",
  };
}

function ensureMapLayer(box) {
  const paint = themePaint();
  const key = `${canvas.width}x${canvas.height}|${box.x},${box.y},${box.w},${box.h}|${document.documentElement.dataset.theme || "dark"}|${MAP_OVERSCAN}`;
  const moving = !!camAnim || cameraShifted(mapPose);
  if (mapLayer && mapLayerKey === key && mapPose && !poseStale(mapPose, mapPose.overscan || 1) && (moving || !cameraShifted(mapPose))) return;
  mapLayerKey = key;
  const poseScale = cam.scale;
  mapPose = { lon: cam.lon, lat: cam.lat, scale: poseScale, overscan: MAP_OVERSCAN };
  mapBuiltAt = performance.now();
  const spread = MAP_OVERSCAN;
  const width = Math.max(1, Math.floor(canvas.width * spread));
  const height = Math.max(1, Math.floor(canvas.height * spread));
  if (!mapLayer) mapLayer = document.createElement("canvas");
  if (mapLayer.width !== width || mapLayer.height !== height) {
    mapLayer.width = width;
    mapLayer.height = height;
  }
  const big = { x: box.x * spread, y: box.y * spread, w: box.w * spread, h: box.h * spread };
  const mctx = mapLayer.getContext("2d");
  mctx.setTransform(1, 0, 0, 1, 0, 0);
  mctx.clearRect(0, 0, width, height);
  mctx.fillStyle = paint.sea;
  mctx.fillRect(0, 0, width, height);
  cam.scale = poseScale / spread;
  try {
    mctx.strokeStyle = paint.grid;
    mctx.lineWidth = 1;
    mctx.beginPath();
    for (let lon = -180; lon <= 180; lon += 30) {
      const [x] = project(lon, 0, big);
      mctx.moveTo(x, 0);
      mctx.lineTo(x, height);
    }
    for (let lat = -60; lat <= 60; lat += 30) {
      const [, y] = project(0, lat, big);
      mctx.moveTo(0, y);
      mctx.lineTo(width, y);
    }
    mctx.stroke();
    mctx.fillStyle = paint.land;
    mctx.strokeStyle = paint.stroke;
    mctx.lineWidth = 0.8;
    for (const feature of state.features) {
      mctx.beginPath();
      traceGeometry(feature.geometry, big, mctx);
      mctx.fill();
      mctx.stroke();
    }
  } finally {
    cam.scale = poseScale;
  }
}

function drawMap(box) {
  mapBox = box;
  ensureMapLayer(box);
  if (mapPose) blitLayer(mapLayer, box, mapPose);
  for (const feature of state.features) {
    const goal = feature === hoverItem || feature === focusItem ? 1 : 0;
    feature.edge += ((goal - feature.edge) * (reduced ? 1 : 0.14));
    if (feature.edge < 0.012) feature.edge = 0;
    feature.flash = Math.max(0, (feature.flash || 0) - (reduced ? 0.1 : 0.04));
    const flash = Math.min(1, feature.flash || 0);
    if (feature.edge <= 0 && flash <= 0) continue;
    const paint = themePaint();
    let fill = feature.edge > 0 ? mixColor(paint.land, paint.edge, feature.edge) : paint.land;
    if (flash > 0) fill = mixColor(fill, paint.flash, flash * 0.85);
    ctx.beginPath();
    traceGeometry(feature.geometry, box);
    ctx.fillStyle = fill;
    ctx.fill();
    ctx.lineWidth = 0.8;
    ctx.strokeStyle = paint.stroke;
    ctx.stroke();
  }
  for (const feature of state.features) {
    if (feature.edge <= 0.02) continue;
    drawFlagFill(feature, box);
  }
  for (const feature of state.features) {
    if (feature.edge <= 0) continue;
    ctx.beginPath();
    traceGeometry(feature.geometry, box);
    ctx.lineWidth = 1.1 + feature.edge * 0.9;
    ctx.strokeStyle = `rgba(247, 244, 238, ${feature.edge})`;
    ctx.stroke();
  }
  const layer = document.getElementById("flagLayer");
  if (layer) layer.hidden = true;
}

const flagImages = new Map();

function loadFlagImage(cc) {
  const src = flagSrc(cc);
  if (!src) return null;
  let img = flagImages.get(cc);
  if (img) return img.complete && img.naturalWidth ? img : null;
  img = new Image();
  img.decoding = "async";
  img.src = src;
  flagImages.set(cc, img);
  return null;
}

function ringScreenBounds(ring, box) {
  let minX = Infinity;
  let maxX = -Infinity;
  let minY = Infinity;
  let maxY = -Infinity;
  for (const [lon, lat] of ring) {
    const [x, y] = project(lon, lat, box);
    minX = Math.min(minX, x);
    maxX = Math.max(maxX, x);
    minY = Math.min(minY, y);
    maxY = Math.max(maxY, y);
  }
  if (!Number.isFinite(minX)) return null;
  return { minX, maxX, minY, maxY, w: maxX - minX, h: maxY - minY };
}

function geometryScreenBounds(geometry, box) {
  const polys = geometry.type === "Polygon" ? [geometry.coordinates] : geometry.coordinates;
  let minX = Infinity;
  let maxX = -Infinity;
  let minY = Infinity;
  let maxY = -Infinity;
  for (const poly of polys) {
    const ring = poly[0];
    if (!ring || !ring.length) continue;
    let minLon = 180;
    let maxLon = -180;
    for (const [lon] of ring) {
      minLon = Math.min(minLon, lon);
      maxLon = Math.max(maxLon, lon);
    }
    if (maxLon - minLon > 180) continue;
    const area = ringScreenBounds(ring, box);
    if (!area) continue;
    minX = Math.min(minX, area.minX);
    maxX = Math.max(maxX, area.maxX);
    minY = Math.min(minY, area.minY);
    maxY = Math.max(maxY, area.maxY);
  }
  if (!Number.isFinite(minX)) return null;
  return { minX, maxX, minY, maxY, w: maxX - minX, h: maxY - minY };
}

function drawFlagFill(feature, box) {
  const img = loadFlagImage(feature.cc);
  const area = geometryScreenBounds(feature.geometry, box);
  if (!img || !area || area.w < 8 || area.h < 8) return;
  const ratio = img.naturalWidth / Math.max(1, img.naturalHeight);
  let dw = area.w;
  let dh = area.w / ratio;
  if (dh < area.h) {
    dh = area.h;
    dw = area.h * ratio;
  }
  const dx = area.minX + (area.w - dw) / 2;
  const dy = area.minY + (area.h - dh) / 2;
  ctx.save();
  ctx.beginPath();
  traceGeometry(feature.geometry, box);
  ctx.clip();
  ctx.globalAlpha = 0.52 * feature.edge;
  ctx.drawImage(img, dx, dy, dw, dh);
  ctx.restore();
}

function placeHostBadge(target) {
  const badge = document.getElementById("hostBadge");
  const mark = document.getElementById("hostMark");
  const label = document.getElementById("hostName");
  const hoster = state.server.hoster || "";
  const name = state.server.hostname || state.server.name || "";
  if (!name) {
    badge.hidden = true;
    return;
  }
  const rect = canvas.getBoundingClientRect();
  const stage = canvas.parentElement.getBoundingClientRect();
  const sx = rect.width / canvas.width;
  const sy = rect.height / canvas.height;
  badge.hidden = false;
  label.textContent = name;
  const slug = String(hoster || "").toLowerCase().replace(/[^a-z0-9]/g, "");
  const src = slug ? `/marks/${slug}.svg` : "";
  mark.onerror = () => { mark.hidden = true; };
  if (src) {
    mark.hidden = false;
    mark.alt = state.server.hoster_name || slug;
    if (mark.getAttribute("src") !== src) mark.src = src;
  } else mark.hidden = true;
  badge.style.left = `${rect.left - stage.left + target[0] * sx + 10}px`;
  badge.style.top = `${rect.top - stage.top + target[1] * sy - 28}px`;
}

function mixColor(from, to, t) {
  const parse = (hex) => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16));
  const a = parse(from);
  const b = parse(to);
  const c = a.map((v, i) => Math.round(v + (b[i] - v) * t));
  return `rgb(${c[0]}, ${c[1]}, ${c[2]})`;
}

function quad(a, c, b, t) {
  const u = 1 - t;
  return [
    u * u * a[0] + 2 * u * t * c[0] + t * t * b[0],
    u * u * a[1] + 2 * u * t * c[1] + t * t * b[1],
  ];
}

function easeOutCubic(t) {
  const u = Math.min(1, Math.max(0, t));
  return 1 - ((1 - u) ** 3);
}

function drawArc(from, to, color, progress, emphasis, fade = 1) {
  const t = easeOutCubic(progress);
  const mx = (from[0] + to[0]) / 2;
  const my = (from[1] + to[1]) / 2;
  const len = Math.hypot(to[0] - from[0], to[1] - from[1]) || 1;
  const lift = Math.min(boxLift(len), len * (emphasis ? 0.22 : 0.14));
  const side = ((from[0] + from[1]) % 2 === 0 ? 1 : -1) * Math.min(18, len * 0.04);
  const control = [mx + side, my - lift];
  const steps = Math.max(24, Math.min(48, Math.floor(len / 12)));
  if (emphasis && t < 1) {
    ctx.beginPath();
    for (let i = 0; i <= steps; i++) {
      const p = quad(from, control, to, i / steps);
      if (i === 0) ctx.moveTo(p[0], p[1]);
      else ctx.lineTo(p[0], p[1]);
    }
    ctx.strokeStyle = color;
    ctx.globalAlpha = 0.12 * fade;
    ctx.lineWidth = 3.2;
    ctx.stroke();
  }
  ctx.beginPath();
  const end = Math.max(2, Math.floor(steps * t));
  for (let i = 0; i <= end; i++) {
    const p = quad(from, control, to, i / steps);
    if (i === 0) ctx.moveTo(p[0], p[1]);
    else ctx.lineTo(p[0], p[1]);
  }
  ctx.strokeStyle = color || "#9eb0c0";
  ctx.globalAlpha = (emphasis ? 0.92 : 0.28) * fade;
  ctx.lineWidth = emphasis ? 2.1 : 1.2;
  ctx.stroke();
  const head = quad(from, control, to, t);
  ctx.globalAlpha = (emphasis ? 1 : 0.45) * fade;
  ctx.fillStyle = color || "#d8dde3";
  ctx.beginPath();
  ctx.arc(head[0], head[1], emphasis ? 3.4 : 2.2, 0, Math.PI * 2);
  ctx.fill();
  if (emphasis) {
    ctx.strokeStyle = "rgba(232, 237, 242, 0.55)";
    ctx.lineWidth = 1;
    ctx.stroke();
  }
  ctx.globalAlpha = 1;
}

function drawImpacts(now) {
  flight.impacts = flight.impacts.filter((item) => now - item.t0 < 700);
  for (const item of flight.impacts) {
    const age = (now - item.t0) / 700;
    const r = 4 + age * 18;
    ctx.beginPath();
    ctx.arc(item.x, item.y, r, 0, Math.PI * 2);
    ctx.strokeStyle = item.color || "#d8dde3";
    ctx.globalAlpha = (1 - age) * 0.55;
    ctx.lineWidth = 1.4;
    ctx.stroke();
  }
  ctx.globalAlpha = 1;
}

function boxLift(len) {
  return Math.min(canvas.height * 0.18, 170);
}

function rowDomain(row) {
  return String(row.host || "").trim().toLowerCase();
}

function domainOk(row) {
  if (!state.domain) return true;
  const host = rowDomain(row);
  if (state.domain === "-") return !host;
  return host === state.domain;
}

function passView(row) {
  if (!row || !state.filters.has(viewKind(row))) return false;
  if (!domainOk(row)) return false;
  if (state.onlyBanned && !state.bans.has(row.ip)) return false;
  return true;
}

function setBans(map) {
  const next = new Map();
  for (const [ip, jails] of Object.entries(map || {})) {
    if (ip) next.set(ip, Array.isArray(jails) ? jails : []);
  }
  state.bans = next;
  state.banRev += 1;
}

function lowerBoundTs(rows, ts) {
  let lo = 0;
  let hi = rows.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (rows[mid].ts < ts) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

let shownCache = [];
let shownKey = "";

function visibleEvents() {
  const from = viewFrom();
  const key = `${state.follow ? 1 : 0}|${state.hits.length}|${state.events.length}|${[...state.filters].join()}|${state.domain}|${state.query}|${state.onlyBanned ? 1 : 0}|${state.banRev}|${state.windowSec}|${Math.floor(state.cursor * 4)}`;
  if (key === shownKey) return shownCache;
  shownKey = key;
  const seen = new Set();
  const rows = [];
  for (let i = lowerBoundTs(state.hits, from); i < state.hits.length; i += 1) {
    const row = state.hits[i];
    if (row.ts > state.cursor) break;
    if (!passView(row) || row.lat == null) continue;
    seen.add(`${row.ts}|${row.ip}|${row.kind}`);
    rows.push(row);
  }
  for (let i = lowerBoundTs(state.events, from); i < state.events.length; i += 1) {
    const ev = state.events[i];
    if (ev.ts > state.cursor) break;
    if (!passView(ev) || ev.lat == null) continue;
    const id = `${ev.ts}|${ev.ip}|${ev.kind}`;
    if (seen.has(id)) continue;
    rows.push(ev);
  }
  rows.sort((a, b) => a.ts - b.ts);
  shownCache = rows;
  return rows;
}

function eventHeatWeight(row) {
  const span = replaySpan() ? Math.max(1, state.cursor - viewFrom()) : state.windowSec;
  const age = Math.min(1, Math.max(0, (state.cursor - row.ts) / Math.max(1, span)));
  const threat = THREAT[row.kind] ?? 0.2;
  const roleBoost = row.role === "botnet" ? 1.35 : row.role === "burst" ? 1.15 : 1;
  return threat * roleBoost * (1 - age * 0.7);
}

function mapHeatColor(t) {
  const u = Math.min(1, Math.max(0, t));
  if (u < 0.35) return mixColor(themePaint().land, "#6d8ea3", u / 0.35);
  if (u < 0.7) return mixColor("#6d8ea3", "#c9a24a", (u - 0.35) / 0.35);
  return mixColor("#c9a24a", "#c24b3c", (u - 0.7) / 0.3);
}

function attackGrade(row) {
  let grade = THREAT[row && row.kind] ?? 0.25;
  if (row && row.role === "botnet") grade += 0.12;
  else if (row && row.role === "burst") grade += 0.06;
  return Math.min(1, grade);
}

function markerFade() {
  const zoom = Math.min(1, Math.max(0, Math.log(Math.max(1, cam.scale)) / Math.log(MAX_SCALE)));
  return 0.55 - zoom * 0.4;
}

let heatLayer = null;
let heatStamp = 0;
let heatPose = null;

function drawPointHeat(box, shown) {
  const nowMs = performance.now();
  const moving = !!camAnim || cameraShifted(heatPose);
  if (heatLayer && heatPose && !poseStale(heatPose, 1) && (moving || nowMs - heatStamp < 280)) {
    blitLayer(heatLayer, box, heatPose);
    return;
  }
  heatStamp = nowMs;
  heatPose = { lon: cam.lon, lat: cam.lat, scale: cam.scale };
  if (!heatLayer) heatLayer = document.createElement("canvas");
  if (heatLayer.width !== canvas.width || heatLayer.height !== canvas.height) {
    heatLayer.width = canvas.width;
    heatLayer.height = canvas.height;
  }
  const hctx = heatLayer.getContext("2d");
  hctx.setTransform(1, 0, 0, 1, 0, 0);
  hctx.clearRect(0, 0, heatLayer.width, heatLayer.height);
  if (shown.length) paintHeatSpots(hctx, box, shown);
  ctx.drawImage(heatLayer, 0, 0);
}

function densityRamp(t) {
  const u = Math.min(1, Math.max(0, t));
  const stops = [
    [0, [28, 108, 64]],
    [0.38, [118, 184, 52]],
    [0.68, [226, 196, 58]],
    [1, [208, 42, 34]],
  ];
  let i = 0;
  while (i < stops.length - 2 && u > stops[i + 1][0]) i += 1;
  const [t0, c0] = stops[i];
  const [t1, c1] = stops[i + 1];
  const k = (u - t0) / Math.max(0.001, t1 - t0);
  return c0.map((v, n) => Math.round(v + (c1[n] - v) * k));
}

let heatInk = null;

function paintHeatSpots(g, box, shown) {
  if (!shown.length) return;
  const width = g.canvas.width;
  const height = g.canvas.height;
  if (!heatInk) heatInk = document.createElement("canvas");
  if (heatInk.width !== width || heatInk.height !== height) {
    heatInk.width = width;
    heatInk.height = height;
  }
  const ink = heatInk.getContext("2d");
  ink.setTransform(1, 0, 0, 1, 0, 0);
  ink.clearRect(0, 0, width, height);
  ink.globalCompositeOperation = "lighter";
  const cellDeg = 0.18;
  const cells = new Map();
  let max = 0;
  for (const row of shown) {
    if (row.lat == null || row.lon == null) continue;
    const key = `${Math.round(row.lon / cellDeg)}:${Math.round(row.lat / cellDeg)}`;
    const w = eventHeatWeight(row);
    const prev = cells.get(key);
    if (!prev) cells.set(key, { lon: row.lon, lat: row.lat, w, n: 1 });
    else {
      prev.lon = (prev.lon * prev.n + row.lon) / (prev.n + 1);
      prev.lat = (prev.lat * prev.n + row.lat) / (prev.n + 1);
      prev.w += w;
      prev.n += 1;
    }
    const cur = cells.get(key);
    if (cur.w > max) max = cur.w;
  }
  max = Math.max(max, 0.001);
  const radius = Math.min(36, Math.max(9, 7 + cam.scale * 1.1));
  const blur = Math.min(16, Math.max(5, radius * 0.42));
  for (const spot of cells.values()) {
    const [x, y] = project(spot.lon, spot.lat, box);
    if (x < box.x - radius || y < box.y - radius || x > box.x + box.w + radius || y > box.y + box.h + radius) continue;
    const t = Math.pow(spot.w / max, 0.55);
    const alpha = 0.16 + t * 0.78;
    const grad = ink.createRadialGradient(x, y, 0, x, y, radius);
    grad.addColorStop(0, `rgba(255,255,255,${alpha})`);
    grad.addColorStop(0.42, `rgba(255,255,255,${alpha * 0.42})`);
    grad.addColorStop(1, "rgba(255,255,255,0)");
    ink.fillStyle = grad;
    ink.beginPath();
    ink.arc(x, y, radius, 0, Math.PI * 2);
    ink.fill();
  }
  ink.globalCompositeOperation = "source-over";
  g.save();
  g.filter = `blur(${blur}px)`;
  g.drawImage(heatInk, 0, 0);
  g.filter = "none";
  g.restore();
  const img = g.getImageData(0, 0, width, height);
  const data = img.data;
  for (let i = 0; i < data.length; i += 4) {
    const a = data[i + 3];
    if (a < 8) {
      data[i + 3] = 0;
      continue;
    }
    const t = Math.min(1, a / 168);
    const [r, gv, b] = densityRamp(t);
    data[i] = r;
    data[i + 1] = gv;
    data[i + 2] = b;
    data[i + 3] = Math.min(198, Math.round(28 + t * 175));
  }
  g.putImageData(img, 0, 0);
}

let banSpotKey = "";
let banSpots = [];

function bannedSpots() {
  const key = `${state.banRev}|${state.hits.length}|${state.events.length}|${state.domain}`;
  if (key === banSpotKey) return banSpots;
  banSpotKey = key;
  const seen = new Set();
  const spots = [];
  const consider = (row) => {
    if (!row || !row.ip || row.lat == null || seen.has(row.ip) || !state.bans.has(row.ip)) return;
    if (!domainOk(row)) return;
    seen.add(row.ip);
    spots.push(row);
  };
  for (let i = state.hits.length - 1; i >= 0; i -= 1) consider(state.hits[i]);
  for (let i = state.events.length - 1; i >= 0; i -= 1) consider(state.events[i]);
  banSpots = spots;
  return spots;
}

function drawBanned(box) {
  const spots = bannedSpots();
  if (!spots.length) return;
  const cells = new Map();
  for (const row of spots) {
    const grade = attackGrade(row);
    const key = `${Math.round(row.lon * 2)}:${Math.round(row.lat * 2)}`;
    const prev = cells.get(key);
    if (!prev || grade > prev.grade) cells.set(key, { row, grade });
  }
  const fade = markerFade();
  ctx.save();
  ctx.lineWidth = 1;
  for (const cell of cells.values()) {
    const [x, y] = project(cell.row.lon, cell.row.lat, box);
    if (x < box.x - 8 || y < box.y - 8 || x > box.x + box.w + 8 || y > box.y + box.h + 8) continue;
    const color = mapHeatColor(cell.grade);
    ctx.strokeStyle = color;
    ctx.fillStyle = color;
    ctx.globalAlpha = fade * 0.5;
    ctx.strokeRect(x - 3.2, y - 3.2, 6.4, 6.4);
    ctx.globalAlpha = fade * 0.28;
    ctx.fillRect(x - 1.1, y - 1.1, 2.2, 2.2);
  }
  ctx.restore();
}

function drawSelectedMarker(box) {
  const row = state.picked || state.selected;
  if (!row || row.lat == null || row.lon == null) return;
  const [x, y] = project(row.lon, row.lat, box);
  const color = (KIND[row.kind] || KIND.probe).color;
  ctx.beginPath();
  ctx.arc(x, y, 8, 0, Math.PI * 2);
  ctx.strokeStyle = color;
  ctx.globalAlpha = 0.45;
  ctx.lineWidth = 1.4;
  ctx.stroke();
  ctx.globalAlpha = 1;
  ctx.fillStyle = color;
  ctx.fillRect(x - 2.4, y - 2.4, 4.8, 4.8);
}

const flight = { primed: false, lastCursor: null, done: new Set(), queued: [], actives: [], trail: [], impacts: [] };

function sameMoment(a, b) {
  return Math.abs(a.ts - b.ts) <= 1;
}

function eventKey(ev) {
  return `${ev.ts}|${ev.ip}|${ev.kind}`;
}

function resetFlights() {
  flight.primed = false;
  flight.lastCursor = null;
  flight.done.clear();
  flight.queued = [];
  flight.actives = [];
  flight.trail = [];
  flight.impacts = [];
}

function enqueueFlight(ev) {
  const key = eventKey(ev);
  if (flight.done.has(key)) return;
  if (flight.queued.some((item) => eventKey(item) === key)) return;
  if (flight.actives.some((item) => eventKey(item.ev) === key)) return;
  const flying = flight.actives.find((item) => sameMoment(item.ev, ev));
  if (flying && performance.now() - flying.t0 < 200) {
    flight.actives.push({ ev, t0: flying.t0 });
    return;
  }
  flight.queued.push(ev);
}

function trimQueue() {
  flight.queued.sort((a, b) => a.ts - b.ts);
  const groups = [];
  for (const ev of flight.queued) {
    const last = groups[groups.length - 1];
    if (last && sameMoment(last[0], ev)) last.push(ev);
    else groups.push([ev]);
  }
  const keepCount = state.playing && state.speed >= 120 ? 24 : 48;
  const kept = groups.slice(-keepCount);
  const keep = new Set(kept.flat().map(eventKey));
  for (const ev of flight.queued) {
    if (!keep.has(eventKey(ev))) flight.done.add(eventKey(ev));
  }
  flight.queued = kept.flat();
}

function launchNext(now) {
  const maxActive = reduced ? 2 : (state.playing && state.speed >= 120 ? 12 : 8);
  while (flight.actives.length < maxActive && flight.queued.length) {
    trimQueue();
    if (!flight.queued.length) return;
    const first = flight.queued[0];
    const batch = [];
    const rest = [];
    for (const ev of flight.queued) {
      if (sameMoment(first, ev) && flight.actives.length + batch.length < maxActive) batch.push(ev);
      else rest.push(ev);
    }
    flight.queued = rest;
    if (!batch.length) break;
    const stagger = flight.actives.length ? 40 : 0;
    const dur = reduced ? 280 : (flight.queued.length > 14 ? 480 : 1100);
    for (const ev of batch) {
      flight.actives.push({ ev, t0: now + stagger, dur });
      pulseCountry(ev.cc, 0.85);
    }
  }
}

function flightCandidates(fromTs, toTs) {
  const rows = [];
  const seen = new Set();
  for (let i = lowerBoundTs(state.hits, fromTs + 0.0001); i < state.hits.length; i += 1) {
    const hit = state.hits[i];
    if (hit.ts > toTs) break;
    if (!passView(hit) || hit.lat == null) continue;
    seen.add(eventKey(hit));
    rows.push(hit);
  }
  for (let i = lowerBoundTs(state.events, fromTs + 0.0001); i < state.events.length; i += 1) {
    const ev = state.events[i];
    if (ev.ts > toTs) break;
    if (!passView(ev) || ev.lat == null) continue;
    const key = eventKey(ev);
    if (seen.has(key)) continue;
    rows.push(ev);
  }
  rows.sort((a, b) => a.ts - b.ts);
  return rows;
}

function markFlightsDoneUpTo(ts) {
  for (const hit of state.hits) {
    if (hit.ts <= ts && hit.lat != null) flight.done.add(eventKey(hit));
  }
  for (const ev of state.events) {
    if (ev.ts <= ts && ev.lat != null) flight.done.add(eventKey(ev));
  }
}

function stepFlights(shown, now) {
  // Bei hohem Replay-Tempo Flüge kürzer halten, damit die Schlange nicht stockt.
  const speedFactor = state.playing && !state.follow ? Math.min(6, Math.max(1, state.speed / 45)) : 1;
  const backlog = flight.queued.length > 14;
  const duration = reduced ? 280 : Math.max(160, (backlog ? 480 : 1100) / speedFactor);
  if (!flight.primed) {
    flight.primed = true;
    if (state.follow) {
      // Live: Historie nicht nachspielen.
      markFlightsDoneUpTo(state.cursor);
      flight.lastCursor = state.cursor;
    } else if (state.playing) {
      // Replay: Cursor kann in diesem Frame schon vorgelaufen sein — von dort aus animieren.
      const step = Math.max(0.05, (state.speed || 1) * 0.05);
      const from = Math.max(earliestTs() - 0.001, state.cursor - step);
      markFlightsDoneUpTo(from);
      flight.lastCursor = from;
      for (const ev of flightCandidates(from, state.cursor)) enqueueFlight(ev);
    } else {
      markFlightsDoneUpTo(state.cursor);
      flight.lastCursor = state.cursor;
    }
    launchNext(now);
    return;
  }
  const previous = flight.lastCursor;
  const current = state.cursor;
  if (previous != null && current + 0.2 < previous) {
    for (const key of [...flight.done]) {
      if (Number(key.slice(0, key.indexOf("|"))) > current) flight.done.delete(key);
    }
    flight.queued = flight.queued.filter((ev) => ev.ts <= current);
    flight.actives = flight.actives.filter((item) => item.ev.ts <= current);
    flight.trail = flight.trail.filter((item) => item.ev.ts <= current);
    flight.impacts = [];
  } else if (previous != null && current > previous + 0.001) {
    const delta = current - previous;
    // Nur Seek / Live-Nachholen stumm überspringen — Replay (auch 10 Min/s) immer animieren.
    const scrubJump = !state.playing && !state.follow && delta > 2.5;
    const liveCatchup = state.follow && delta > 8;
    if (scrubJump || liveCatchup) {
      markFlightsDoneUpTo(current);
      flight.queued = [];
      flight.actives = [];
      flight.trail = [];
      flight.impacts = [];
    } else {
      for (const ev of flightCandidates(previous, current)) enqueueFlight(ev);
    }
  }
  flight.lastCursor = current;
  const still = [];
  for (const item of flight.actives) {
    if (now < item.t0) {
      still.push(item);
      continue;
    }
    if (now - item.t0 >= (item.dur || duration)) {
      flight.done.add(eventKey(item.ev));
      flight.trail.push({ ev: item.ev, until: now + 2200, color: arcColor(item.ev) });
      flight.impacts.push({
        x: 0, y: 0, t0: now,
        color: arcColor(item.ev),
        pending: true,
        ev: item.ev,
      });
      pulseCountry(item.ev.cc, 1);
    } else still.push(item);
  }
  flight.actives = still;
  launchNext(now);
}

let uiStamp = 0;

function render() {
  const now = performance.now();
  const dt = Math.min(0.1, (now - state.lastFrame) / 1000);
  state.lastFrame = now;
  if (state.playing && !state.follow) {
    state.cursor += dt * state.speed;
    const end = latestTs();
    if (state.cursor >= end) {
      state.cursor = end;
      state.playing = false;
      syncPlay();
    }
    syncScrub();
  } else if (state.follow) {
    const end = Math.max(latestTs(), Date.now() / 1000);
    state.cursor = end;
    syncScrub();
  }

  resize();
  easeCam(now);
  const box = viewBox();
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = themePaint().sea;
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.save();
  ctx.beginPath();
  ctx.rect(box.x, box.y, box.w, box.h);
  ctx.clip();
  if (state.features.length) drawMap(box);

  const shown = visibleEvents();
  drawPointHeat(box, shown);
  drawBanned(box);

  const target = project(state.server.lon, state.server.lat, box);
  stepFlights(shown, now);
  drawSelectedMarker(box);

  flight.trail = flight.trail.filter((item) => item.until > now && item.ev.ts <= state.cursor);
  for (const item of flight.trail) {
    const origin = project(item.ev.lon, item.ev.lat, box);
    const fade = Math.max(0.12, (item.until - now) / 2200);
    drawArc(origin, target, item.color || "#9eb0c0", 1, false, fade);
  }
  for (const item of flight.actives) {
    if (now < item.t0) continue;
    const ev = item.ev;
    const origin = project(ev.lon, ev.lat, box);
    const progress = Math.min(1, (now - item.t0) / (item.dur || (reduced ? 280 : 1100)));
    drawArc(origin, target, arcColor(ev), progress, true, 1);
  }
  for (const item of flight.impacts) {
    if (item.pending) {
      item.x = target[0];
      item.y = target[1];
      item.pending = false;
    }
  }
  drawImpacts(now);

  ctx.fillStyle = "#d8dde3";
  ctx.fillRect(target[0] - 3.5, target[1] - 3.5, 7, 7);
  ctx.strokeStyle = "#9aa3ad";
  ctx.lineWidth = 1;
  ctx.strokeRect(target[0] - 3.5, target[1] - 3.5, 7, 7);
  ctx.restore();
  placeHostBadge(target);
  ctx.strokeStyle = "rgba(168, 184, 170, 0.35)";
  ctx.lineWidth = 1.2;
  ctx.strokeRect(box.x, box.y, box.w, box.h);
  if (now - uiStamp > (camAnim ? 700 : 320)) {
    uiStamp = now;
    paintCountry();
    document.getElementById("quiet").hidden = shown.length > 0 || !state.features.length || (state.onlyBanned && bannedSpots().length > 0);
    paintStats();
    paintAnalytics();
    paintFeed(shown);
    paintDomains();
    paintBanButton();
  }
  keepPlayheadInView();
  drawWave();
  requestAnimationFrame(render);
}

function timeRange() {
  const dataStart = Math.min(
    state.events.length ? state.events[0].ts : Infinity,
    state.hits.length ? state.hits[0].ts : Infinity,
  );
  const dataEnd = Math.max(
    state.events.length ? state.events[state.events.length - 1].ts : 0,
    state.hits.length ? state.hits[state.hits.length - 1].ts : 0,
    state.cursor,
  );
  // Replay: festes Log-Ende — sonst wackeln die Balken durch Date.now().
  if (!state.follow) {
    const start = Number.isFinite(dataStart) ? dataStart : state.cursor - 3600;
    const end = Math.max(dataEnd, start + 1);
    return { start, end, span: Math.max(1, end - start) };
  }
  const end = Math.max(dataEnd, Date.now() / 1000, state.cursor);
  const start = Number.isFinite(dataStart) ? Math.min(dataStart, end - 3600) : end - 3600;
  return { start, end, span: Math.max(1, end - start) };
}

let waveSpanShown = 0;
let waveFlight = null;

function targetWaveSpan(full) {
  const minSpan = 8;
  const maxZoom = Math.max(1, full.span / minSpan);
  state.waveZoom = Math.min(maxZoom, Math.max(1, state.waveZoom || 1));
  if (state.follow) return Math.min(full.span, LIVE_SPAN);
  return Math.max(minSpan, full.span / state.waveZoom);
}

function waveBarCount() {
  return Math.max(
    48,
    Math.min(220, Math.floor((waveCssW || 800) / (1.4 + Math.log2(Math.max(1, state.waveZoom)) * 2.4))),
  );
}

function startWaveFlight(toSpan, pinEnd) {
  const full = timeRange();
  const fromSpan = Math.max(8, waveSpanShown || toSpan);
  const fromStart = Number.isFinite(state.waveOrigin) ? state.waveOrigin : full.end - fromSpan;
  const span = Math.max(8, Math.min(full.span, toSpan));
  const toStart = pinEnd ? Math.max(full.start, full.end - span) : full.start;
  const bars = waveBarCount();
  const binSec = Math.max(0.05, span / bars);
  const origin = Math.floor(toStart / binSec) * binSec;
  const count = Math.min(4800, Math.ceil((toStart + span - origin) / binSec) + 2);
  const snap = document.createElement("canvas");
  if (wave.width && wave.height) {
    snap.width = wave.width;
    snap.height = wave.height;
    snap.getContext("2d").drawImage(wave, 0, 0);
  }
  waveFlight = {
    t0: performance.now(),
    dur: 860,
    fromStart,
    fromSpan,
    toSpan: span,
    toStart,
    pinEnd: !!pinEnd,
    snap: snap.width ? snap : null,
    snapStart: fromStart,
    snapSpan: fromSpan,
    bake: bakeWave(binSec, origin, count),
  };
}

function bakeWave(binSec, origin, count) {
  const counts = new Array(count).fill(0);
  const peaks = new Array(count).fill(0);
  const attacks = new Array(count).fill(0);
  const selves = new Array(count).fill(0);
  const t0 = origin;
  const t1 = origin + count * binSec;
  const ingest = (row) => {
    if (!passView(row) || row.ts < t0 || row.ts >= t1) return;
    const index = Math.floor((row.ts - origin) / binSec);
    if (index < 0 || index >= count) return;
    counts[index] += 1;
    if (isSelf(row)) {
      selves[index] += 1;
      return;
    }
    const threat = THREAT[row.kind] ?? 0.2;
    peaks[index] = Math.max(peaks[index], threat);
    if (threat >= 0.7 || ATTACKS.has(row.kind)) attacks[index] += 1;
  };
  for (const hit of state.hits) ingest(hit);
  for (const ev of state.events) ingest(ev);
  const max = Math.max(1, ...counts);
  const maxAttacks = Math.max(1, ...attacks);
  const bins = counts.map((n, i) => {
    if (!n) return null;
    const peak = peaks[i];
    const attackAmp = Math.pow(attacks[i] / maxAttacks, 0.52);
    const volumeAmp = Math.pow(n / max, 0.5);
    return {
      amp: Math.min(1, Math.max(volumeAmp, attackAmp, peak >= 0.7 ? 0.28 : 0)),
      heat: Math.min(1, peak * 0.82 + (attacks[i] ? 0.18 : 0)),
      ts: origin + (i + 0.5) * binSec,
      self: selves[i] > 0 && selves[i] === n,
    };
  });
  return { binSec, origin, bins };
}

function easeInOut(t) {
  const x = Math.min(1, Math.max(0, t));
  return x < 0.5 ? 2 * x * x : 1 - ((-2 * x + 2) ** 2) / 2;
}

function waveView() {
  const full = timeRange();
  let span;
  let start;
  if (waveFlight) {
    const flight = waveFlight;
    const t = Math.min(1, (performance.now() - flight.t0) / flight.dur);
    const u = easeInOut(t);
    const fromLog = Math.log(Math.max(8, flight.fromSpan));
    const toLog = Math.log(Math.max(8, flight.toSpan));
    span = Math.exp(fromLog + (toLog - fromLog) * u);
    if (flight.pinEnd) {
      const fromEnd = flight.fromStart + flight.fromSpan;
      const toEnd = flight.toStart + flight.toSpan;
      const end = fromEnd + (toEnd - fromEnd) * u;
      start = end - span;
    } else {
      start = flight.fromStart + (flight.toStart - flight.fromStart) * u;
    }
    const lo = Math.min(flight.fromStart, flight.toStart);
    const hi = Math.max(flight.fromStart + flight.fromSpan, flight.toStart + flight.toSpan);
    span = Math.max(8, Math.min(Math.max(8, hi - lo), span));
    start = Math.min(Math.max(start, lo), Math.max(lo, hi - span));
    if (t >= 1) waveFlight = null;
  }
  if (!waveFlight) {
    span = targetWaveSpan(full);
    if (state.follow) start = full.end - span;
    else start = state.waveOrigin == null ? full.start : state.waveOrigin;
    span = Math.max(8, Math.min(full.span, span));
    start = Math.min(Math.max(start, full.start), Math.max(full.start, full.end - span));
  }
  waveSpanShown = span;
  state.waveOrigin = start;
  return { start, end: start + span, span };
}

function keepPlayheadInView() {
  if (waveFlight || state.follow || !state.playing) return;
  const full = timeRange();
  const view = waveView();
  const span = view.span;
  let start = view.start;
  const right = start + span * 0.9;
  const left = start + span * 0.1;
  if (state.cursor > right) start = state.cursor - span * 0.82;
  else if (state.cursor < left) start = state.cursor - span * 0.18;
  else return;
  start = Math.min(Math.max(start, full.start), Math.max(full.start, full.end - span));
  if (Math.abs(start - (state.waveOrigin ?? start)) > 0.05) {
    state.waveOrigin = start;
    waveKey = "";
  }
}

function panWave(deltaPx, widthPx) {
  if (!widthPx) return;
  state.follow = false;
  const view = waveView();
  const next = (state.waveOrigin ?? view.start) + (deltaPx / widthPx) * view.span;
  state.waveOrigin = next;
  waveView();
  waveKey = "";
  syncLive();
}

let waveCssW = 0;
let waveCssH = 0;
let waveMeasureAt = 0;

function drawFrozenWave(flight, start, span, width, height, dpr) {
  wctx.clearRect(0, 0, width, height);
  wctx.fillStyle = themePaint().sea;
  wctx.fillRect(0, 0, width, height);
  const bake = flight.bake;
  const barW = Math.max(dpr, (bake.binSec / span) * width * 0.86);
  const mid = height / 2;
  const i0 = Math.max(0, Math.floor((start - bake.origin) / bake.binSec) - 1);
  const i1 = Math.min(bake.bins.length, Math.ceil((start + span - bake.origin) / bake.binSec) + 1);
  for (let i = i0; i < i1; i += 1) {
    const bin = bake.bins[i];
    if (!bin || bin.amp <= 0) continue;
    const x = ((bin.ts - start) / span) * width - barW / 2;
    if (x + barW < 0 || x > width) continue;
    const bar = Math.max(bin.heat >= 0.7 ? 3 : 1.5, bin.amp * height * 0.48);
    wctx.fillStyle = bin.self ? "rgba(122, 160, 184, 0.9)" : ampColor(bin.amp, bin.heat);
    wctx.fillRect(x, mid - bar, barW, bar * 2);
  }
  if (flight.snap) {
    const t = Math.min(1, (performance.now() - flight.t0) / flight.dur);
    const u = easeInOut(t);
    const cover = u < 0.72 ? 1 : Math.max(0, 1 - (u - 0.72) / 0.28);
    wctx.save();
    wctx.globalAlpha = cover;
    const x = ((flight.snapStart - start) / span) * width;
    const w = (flight.snapSpan / span) * width;
    wctx.drawImage(flight.snap, x, 0, w, height);
    wctx.restore();
  }
  wctx.strokeStyle = "rgba(90, 100, 110, 0.55)";
  wctx.beginPath();
  wctx.moveTo(0, mid);
  wctx.lineTo(width, mid);
  wctx.stroke();
  const head = state.follow
    ? width - dpr
    : Math.min(width - dpr, Math.max(dpr, ((state.cursor - start) / span) * width));
  wctx.fillStyle = "#e8edf2";
  wctx.fillRect(head - dpr, 0, dpr * 1.8, height);
  const cssW = width / dpr;
  for (const hostId of ["waveMarks", "waveStars"]) {
    const host = document.getElementById(hostId);
    if (!host) continue;
    for (const btn of host.children) {
      const ts = Number(btn.dataset.ts);
      if (!Number.isFinite(ts)) continue;
      const px = ((ts - start) / span) * cssW;
      btn.style.left = `${px}px`;
      btn.classList.toggle("is-off", px < -16 || px > cssW + 16);
    }
  }
  waveGeom = { start, span, slot: (bake.binSec / span) * width, scrollPx: 0, dpr, binSec: bake.binSec, height };
}

function drawWave() {
  const nowMs = performance.now();
  if (!waveCssW || nowMs - waveMeasureAt > 400) {
    waveMeasureAt = nowMs;
    const rect = wave.getBoundingClientRect();
    waveCssW = rect.width;
    waveCssH = rect.height;
  }
  const dpr = Math.min(2, devicePixelRatio || 1);
  const width = Math.max(1, Math.floor(waveCssW * dpr));
  const height = Math.max(1, Math.floor(waveCssH * dpr));
  if (wave.width !== width || wave.height !== height) {
    wave.width = width;
    wave.height = height;
    waveKey = "";
  }
  const flight = waveFlight;
  const { start, span } = waveView();
  if (flight && waveFlight && flight.bake) {
    drawFrozenWave(flight, start, span, width, height, dpr);
    return;
  }
  // Weiter rausgezoomt = mehr Balken, damit Spitzen nicht zu einem Block verschmieren.
  const bars = waveBarCount();
  const binSec = span / bars;
  // Absolutes Zeitraster + Sub-Pixel-Scroll: stabil im Replay, fließend im Live.
  const leftBin = Math.floor(start / binSec);
  const scrollFrac = Math.min(1, Math.max(0, start / binSec - leftBin));
  const slot = width / bars;
  const scrollPx = scrollFrac * slot;
  const drawBins = bars + 1;
  const key = `${state.selfIp}|${state.events.length}|${state.hits.length}|${[...state.filters].join()}|${state.domain}|${state.onlyBanned ? 1 : 0}|${state.banRev}|${bars}|${leftBin}|${binSec.toFixed(4)}|${state.waveZoom.toFixed(3)}|${state.follow ? 1 : 0}`;
  if (key !== waveKey) {
    waveKey = key;
    const counts = new Array(drawBins).fill(0);
    const peaks = new Array(drawBins).fill(0);
    const attacks = new Array(drawBins).fill(0);
    const selves = new Array(drawBins).fill(0);
    const t0 = leftBin * binSec;
    const t1 = t0 + drawBins * binSec;
    const ingest = (row) => {
      if (!passView(row)) return;
      if (row.ts < t0 || row.ts >= t1) return;
      const index = Math.floor(row.ts / binSec) - leftBin;
      if (index < 0 || index >= drawBins) return;
      counts[index] += 1;
      if (isSelf(row)) {
        selves[index] += 1;
        return;
      }
      const threat = THREAT[row.kind] ?? 0.2;
      peaks[index] = Math.max(peaks[index], threat);
      if (threat >= 0.7 || ATTACKS.has(row.kind)) attacks[index] += 1;
    };
    for (const hit of state.hits) ingest(hit);
    for (const ev of state.events) ingest(ev);
    const max = Math.max(1, ...counts);
    const maxAttacks = Math.max(1, ...attacks);
    const zoomOut = state.waveZoom <= 1.35;
    waveBins = counts.map((count, i) => {
      if (!count) return { amp: 0, heat: 0, ts: leftBin * binSec + i * binSec };
      const peak = peaks[i];
      const attackAmp = Math.pow(attacks[i] / maxAttacks, 0.52);
      const volumeAmp = Math.pow(count / max, zoomOut ? 0.42 : 0.58);
      const amp = Math.min(1, Math.max(volumeAmp, attackAmp * (zoomOut ? 1 : 0.85), peak >= 0.7 ? 0.28 : 0));
      const heat = Math.min(1, peak * 0.82 + (attacks[i] ? 0.18 : 0));
      return {
        amp,
        heat,
        ts: leftBin * binSec + (i + 0.5) * binSec,
        attacks: attacks[i],
        self: selves[i] > 0 && selves[i] === count,
      };
    });
  }
  wctx.clearRect(0, 0, width, height);
  wctx.fillStyle = themePaint().sea;
  wctx.fillRect(0, 0, width, height);
  const x0 = ((state.cursor - state.windowSec - start) / span) * width;
  const x1 = ((state.cursor - start) / span) * width;
  wctx.fillStyle = "rgba(216, 221, 227, 0.05)";
  wctx.fillRect(x0, 0, Math.max(1, x1 - x0), height);
  const mid = height / 2;
  const barW = Math.max(dpr * 1.2, slot - dpr * 0.4);
  wctx.save();
  wctx.beginPath();
  wctx.rect(0, 0, width, height);
  wctx.clip();
  waveBins.forEach((bin, index) => {
    const amp = typeof bin === "number" ? bin : bin.amp;
    const heat = typeof bin === "number" ? 0.35 : bin.heat;
    if (amp <= 0) return;
    const bar = Math.max(heat >= 0.7 ? 3 : 1.5, amp * height * 0.48);
    const x = index * slot - scrollPx;
    if (x + barW < 0 || x > width) return;
    // Je größer der Balken, desto dunkler; Threat färbt leicht Richtung Rot.
    let fill = bin.self ? "rgba(122, 160, 184, 0.9)" : ampColor(amp, heat);
    if (index === waveHover) fill = liftColor(fill, 0.34);
    wctx.fillStyle = fill;
    wctx.fillRect(x, mid - bar, barW, bar * 2);
  });
  wctx.restore();
  wctx.strokeStyle = "rgba(90, 100, 110, 0.55)";
  wctx.beginPath();
  wctx.moveTo(0, mid);
  wctx.lineTo(width, mid);
  wctx.stroke();
  const head = state.follow
    ? width - dpr
    : Math.min(width - dpr, Math.max(dpr, ((state.cursor - start) / span) * width));
  // Indikator wie zuvor: heller Strich + Dreieck
  wctx.fillStyle = "rgba(216, 221, 227, 0.22)";
  wctx.fillRect(head - dpr * 3, 0, dpr * 6, height);
  wctx.fillStyle = "#e8edf2";
  wctx.fillRect(head - dpr, 0, dpr * 1.8, height);
  wctx.beginPath();
  wctx.moveTo(head, dpr * 2);
  wctx.lineTo(head - dpr * 4, dpr * 8);
  wctx.lineTo(head + dpr * 4, dpr * 8);
  wctx.closePath();
  wctx.fillStyle = "#e8edf2";
  wctx.fill();

  waveGeom = { start, span, slot, scrollPx, dpr, binSec, height };
  paintWaveMarks(start, span, width, height, slot, scrollPx, dpr);
  paintWaveStars(start, span);

  const label = document.getElementById("cursorLabel");
  if (label) {
    const hover = waveHover >= 0 ? waveBins[waveHover] : null;
    if (!hover || hover.ts == null) {
      label.hidden = true;
    } else {
      const box = barBox(waveHover);
      const cssW = width / dpr;
      const pct = box ? (box.cx / cssW) * 100 : 50;
      label.hidden = false;
      label.textContent = formatTime(hover.ts);
      label.style.left = `${pct}%`;
      label.dataset.edge = pct < 12 ? "left" : pct > 88 ? "right" : "mid";
    }
  }
}

let waveMarkKey = "";
let waveHover = -1;
let waveGeom = { start: 0, span: 1, slot: 1, scrollPx: 0, dpr: 1, binSec: 1, height: 1 };

function warningIconSvg() {
  return `<svg viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M8 1.4 1.2 13.4h13.6L8 1.4zm0 3.3.9 5.1H7.1L8 4.7zM8 12.2a.9.9 0 1 1 0-1.8.9.9 0 0 1 0 1.8z"/></svg>`;
}

function starIconSvg() {
  return `<svg viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M8 1.4 9.7 6.2h5l-4 3.1 1.5 4.8L8 11.2 3.8 14.1 5.3 9.3l-4-3.1h5z"/></svg>`;
}

function loadStars() {
  try {
    const raw = JSON.parse(localStorage.getItem("livemap.stars") || "[]");
    state.stars = Array.isArray(raw) ? raw.map(Number).filter(Number.isFinite).slice(0, 48) : [];
  } catch (err) {
    state.stars = [];
  }
}

function saveStars() {
  try { localStorage.setItem("livemap.stars", JSON.stringify(state.stars)); } catch (err) { /* ignore */ }
}

function starTolerance() {
  return Math.max(0.4, waveGeom.binSec || 1);
}

function starIndex(ts) {
  const tol = starTolerance();
  return state.stars.findIndex((item) => Math.abs(item - ts) <= tol);
}

function setStar(ts, on) {
  const index = starIndex(ts);
  if (on && index < 0) {
    state.stars.push(ts);
    if (state.stars.length > 48) state.stars.shift();
  } else if (!on && index >= 0) state.stars.splice(index, 1);
  saveStars();
  waveStarKey = "";
  waveMarkKey = "";
}

function liftColor(rgb, amount) {
  const parts = String(rgb).match(/\d+/g);
  if (!parts || parts.length < 3) return rgb;
  const next = parts.slice(0, 3).map((part) => Math.min(255, Math.round(Number(part) + (255 - Number(part)) * amount)));
  return `rgb(${next[0]}, ${next[1]}, ${next[2]})`;
}

function binAtClientX(clientX) {
  if (!waveGeom.slot) return null;
  const rect = wave.getBoundingClientRect();
  const x = (clientX - rect.left) * waveGeom.dpr;
  const index = Math.floor((x + waveGeom.scrollPx) / waveGeom.slot);
  const bin = waveBins[index];
  if (!bin || !bin.amp || bin.ts == null) return null;
  return { index, ts: bin.ts };
}

function starBin(ts) {
  const half = starTolerance();
  let best = -1;
  let dist = half;
  for (let i = 0; i < waveBins.length; i += 1) {
    const bin = waveBins[i];
    if (!bin || !bin.amp || bin.ts == null) continue;
    const gap = Math.abs(bin.ts - ts);
    if (gap < dist) {
      dist = gap;
      best = i;
    }
  }
  return best;
}

function barBox(index) {
  const bin = waveBins[index];
  if (!bin) return null;
  const { slot, scrollPx, dpr, height } = waveGeom;
  const amp = bin.amp || 0;
  const heat = bin.heat || 0;
  const bar = Math.max(heat >= 0.7 ? 3 : 1.5, amp * height * 0.48);
  const barW = Math.max(dpr * 1.2, slot - dpr * 0.4);
  const x = index * slot - scrollPx;
  return {
    cx: (x + barW / 2) / dpr,
    top: Math.max(0, (height / 2 - bar) / dpr - 13),
  };
}

function openStarMenu(x, y, ts) {
  const menu = document.getElementById("ctx");
  if (!menu || ts == null) return;
  menu.replaceChildren();
  const marked = starIndex(ts) >= 0;
  const btn = document.createElement("button");
  btn.type = "button";
  btn.textContent = marked ? "Stern entfernen" : "Stern setzen";
  btn.addEventListener("click", (event) => {
    event.stopPropagation();
    closeContextMenu();
    setStar(ts, !marked);
  });
  menu.appendChild(btn);
  menu.hidden = false;
  const pad = 8;
  const width = menu.offsetWidth || 160;
  const height = menu.offsetHeight || 36;
  menu.style.left = `${Math.min(x, window.innerWidth - width - pad)}px`;
  menu.style.top = `${Math.min(y, window.innerHeight - height - pad)}px`;
}

function paintWaveMarks(start, span, width, height, slot, scrollPx, dpr) {
  const host = document.getElementById("waveMarks");
  if (!host || !waveBins.length) return;
  const candidates = [];
  const selfMarks = [];
  for (let i = 0; i < waveBins.length; i += 1) {
    const bin = waveBins[i];
    if (!bin || !bin.amp) continue;
    const prev = waveBins[i - 1]?.amp || 0;
    const next = waveBins[i + 1]?.amp || 0;
    const localPeak = bin.amp >= prev && bin.amp >= next;
    if (bin.self) {
      if (localPeak) selfMarks.push({ i, amp: bin.amp, self: true, ts: bin.ts || start });
      continue;
    }
    if (i === 0 || i === waveBins.length - 1 || !localPeak) continue;
    if (bin.amp < 0.52 && bin.heat < 0.72) continue;
    candidates.push({ i, amp: bin.amp, heat: bin.heat || 0, ts: bin.ts || start });
  }
  candidates.sort((a, b) => (b.heat - a.heat) || (b.amp - a.amp));
  const picked = [];
  for (const item of candidates) {
    if (picked.length >= 8) break;
    if (picked.some((other) => Math.abs(other.i - item.i) < 3)) continue;
    picked.push(item);
  }
  selfMarks.sort((a, b) => b.amp - a.amp);
  for (const item of selfMarks) {
    if (picked.filter((other) => other.self).length >= 8) break;
    if (picked.some((other) => Math.abs(other.i - item.i) < 3)) continue;
    picked.push(item);
  }
  picked.sort((a, b) => a.i - b.i);
  const key = picked.map((p) => `${p.self ? "s" : "w"}${Math.round(p.ts)}:${(p.heat || 0).toFixed(2)}`).join("|");
  const cssWidth = width / dpr;
  const place = (btn, item) => {
    const xCss = ((item.i * slot - scrollPx) + slot * 0.5) / dpr;
    btn.style.left = `${xCss}px`;
    btn.classList.toggle("is-off", xCss < -16 || xCss > cssWidth + 16);
    btn.classList.toggle("on", Math.abs((state.cursor || 0) - item.ts) <= starTolerance());
  };
  if (key !== waveMarkKey || host.children.length !== picked.length) {
    waveMarkKey = key;
    host.replaceChildren();
    for (const item of picked) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = item.self
        ? "wave-mark self"
        : `wave-mark${item.heat >= 0.85 || item.amp >= 0.85 ? " danger" : " warn"}`;
      btn.dataset.ts = String(item.ts);
      btn.setAttribute("aria-label", item.self ? "Eigener Client" : item.heat >= 0.85 ? "Starke Spitze" : "Auffällige Spitze");
      if (item.self) {
        const icon = document.createElement("img");
        icon.src = "/marks/self.svg";
        icon.alt = "";
        btn.appendChild(icon);
      } else {
        btn.innerHTML = warningIconSvg();
      }
      btn.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        if (state.follow) return;
        state.playing = false;
        state.cursor = item.ts;
        state.born.clear();
        resetFlights();
        syncLive();
        syncPlay();
        feed.dataset.key = "";
      });
      btn.addEventListener("pointerenter", () => {
        waveHover = item.i;
      });
      btn.addEventListener("contextmenu", (event) => {
        event.preventDefault();
        event.stopPropagation();
        openStarMenu(event.clientX, event.clientY, item.ts);
      });
      place(btn, item);
      host.appendChild(btn);
    }
  } else {
    picked.forEach((item, index) => {
      const btn = host.children[index];
      if (btn) place(btn, item);
    });
  }
}

let waveStarKey = "";

function paintWaveStars(start, span) {
  const host = document.getElementById("waveStars");
  if (!host) return;
  const cssW = waveCssW || 1;
  const cssH = waveCssH || 52;
  const placed = [];
  const seen = new Set();
  for (const ts of state.stars) {
    const index = starBin(ts);
    if (index < 0 || seen.has(index)) continue;
    seen.add(index);
    const box = barBox(index);
    if (!box || box.cx < -16 || box.cx > cssW + 16) continue;
    placed.push({ ts: waveBins[index].ts, index, cx: box.cx, top: box.top });
  }
  placed.sort((a, b) => a.cx - b.cx);
  const key = placed.map((item) => item.ts.toFixed(2)).join(",");
  if (key !== waveStarKey) {
    waveStarKey = key;
    host.replaceChildren();
    for (const item of placed) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "wave-star";
      btn.dataset.ts = String(item.ts);
      btn.setAttribute("aria-label", "Stern");
      btn.innerHTML = starIconSvg();
      btn.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        if (state.follow) return;
        state.playing = false;
        state.cursor = item.ts;
        state.born.clear();
        resetFlights();
        syncLive();
        syncPlay();
        feed.dataset.key = "";
      });
      btn.addEventListener("contextmenu", (event) => {
        event.preventDefault();
        event.stopPropagation();
        openStarMenu(event.clientX, event.clientY, item.ts);
      });
      btn.addEventListener("pointerenter", () => {
        waveHover = item.index;
      });
      host.appendChild(btn);
    }
  }
  const buttons = [...host.children];
  placed.forEach((item, index) => {
    const btn = buttons[index];
    const box = barBox(item.index);
    if (!btn || !box) return;
    btn.style.left = `${box.cx}px`;
    btn.style.top = `${box.top}px`;
  });
}

function ampColor(amp, heat = 0) {
  // Größe steuert Helligkeit (größer = dunkler), Threat steuert Rotanteil.
  const a = Math.min(1, Math.max(0, amp));
  const h = Math.min(1, Math.max(0, heat));
  const light = [
    [0, [118, 124, 132]],
    [0.35, [112, 96, 90]],
    [0.65, [120, 62, 52]],
    [1, [72, 24, 22]],
  ];
  let i = 0;
  while (i < light.length - 2 && a > light[i + 1][0]) i += 1;
  const [t0, c0] = light[i];
  const [t1, c1] = light[i + 1];
  const u = (a - t0) / Math.max(0.001, t1 - t0);
  let rgb = c0.map((v, n) => Math.round(v + (c1[n] - v) * u));
  if (h > 0.45) {
    const k = (h - 0.45) / 0.55;
    rgb = [
      Math.min(210, Math.round(rgb[0] + 18 * k)),
      Math.max(20, Math.round(rgb[1] - 12 * k)),
      Math.max(18, Math.round(rgb[2] - 8 * k)),
    ];
  }
  return `rgb(${rgb[0]}, ${rgb[1]}, ${rgb[2]})`;
}

function heatColor(t) {
  const stops = [
    [0, [90, 98, 108]],
    [0.25, [95, 143, 107]],
    [0.55, [201, 162, 74]],
    [0.8, [194, 95, 58]],
    [1, [180, 52, 48]],
  ];
  let i = 0;
  while (i < stops.length - 2 && t > stops[i + 1][0]) i += 1;
  const [t0, c0] = stops[i];
  const [t1, c1] = stops[i + 1];
  const u = (t - t0) / Math.max(0.001, t1 - t0);
  const rgb = c0.map((v, n) => Math.round(v + (c1[n] - v) * u));
  return `rgb(${rgb[0]}, ${rgb[1]}, ${rgb[2]})`;
}

function seekWave(clientX, options = {}) {
  const rect = wave.getBoundingClientRect();
  const ratio = Math.min(1, Math.max(0, (clientX - rect.left) / rect.width));
  const { start, span } = waveView();
  const next = start + span * ratio;
  const jumped = Math.abs(next - state.cursor) > 0.35;
  state.follow = false;
  if (options.pause !== false) state.playing = false;
  state.cursor = next;
  if (jumped) {
    state.born.clear();
    resetFlights();
  }
  if (options.play === true) state.playing = true;
  if (options.toggle === true) state.playing = !state.playing;
  syncLive();
  syncPlay();
  feed.dataset.key = "";
  waveKey = "";
}

function earliestTs() {
  const ev = state.events.length ? state.events[0].ts : Infinity;
  const hit = state.hits.length ? state.hits[0].ts : Infinity;
  const ts = Math.min(ev, hit);
  return Number.isFinite(ts) ? ts : Date.now() / 1000 - 3600;
}

function latestTs() {
  const ev = state.events.length ? state.events[state.events.length - 1].ts : 0;
  const hit = state.hits.length ? state.hits[state.hits.length - 1].ts : 0;
  return Math.max(ev, hit, Date.now() / 1000 - 3600);
}

function windowStatLabel(sec) {
  const known = WINDOWS.find(([value]) => value === sec);
  if (known) return known[1];
  if (sec % 3600 === 0) return `${sec / 3600} Std`;
  if (sec % 60 === 0) return `${sec / 60} Min`;
  return `${sec} Sek`;
}

function rowsBetween(from, now) {
  const seen = new Set();
  const rows = [];
  const take = (row) => {
    if (!row || row.ts < from || row.ts > now || !passView(row)) return;
    const id = `${row.ts}|${row.ip}|${row.kind}`;
    if (seen.has(id)) return;
    seen.add(id);
    rows.push(row);
  };
  for (const row of state.hits) take(row);
  for (const row of state.events) take(row);
  return rows;
}

function paintStats() {
  const now = state.follow ? Date.now() / 1000 + 5 : state.cursor;
  const span = state.follow ? LIVE_SPAN : state.windowSec;
  const windowRows = rowsBetween(now - span, now);
  const hourRows = rowsBetween(now - 3600, now);
  const countries = new Set(windowRows.map((row) => row.cc).filter(Boolean));
  const ips = new Set(windowRows.map((row) => row.ip).filter(Boolean));
  document.getElementById("statWindow").textContent = windowRows.length.toLocaleString("de-DE");
  const windowLabel = document.getElementById("statWindowLabel");
  if (windowLabel) windowLabel.textContent = state.follow ? "2 Min" : windowStatLabel(state.windowSec);
  document.getElementById("statHour").textContent = hourRows.length.toLocaleString("de-DE");
  document.getElementById("statCountries").textContent = countries.size.toLocaleString("de-DE");
  const ipEl = document.getElementById("statIps");
  if (ipEl) ipEl.textContent = ips.size.toLocaleString("de-DE");
  paintTopIps(windowRows);
  paintHeader(windowRows, now);
}

let topIpKey = "";

function paintTopIps(shown) {
  const host = document.getElementById("topIps");
  if (!host) return;
  const rows = shown.length ? shown : logRows();
  const byIp = new Map();
  for (const row of rows) {
    if (!row.ip) continue;
    const cur = byIp.get(row.ip) || {
      ip: row.ip, cc: row.cc, name: row.name, count: 0, heat: 0, role: row.role || "traffic",
    };
    cur.count += 1;
    cur.heat = Math.max(cur.heat, row.heat || THREAT[row.kind] || 0);
    if ((row.role === "botnet" || row.role === "burst") && cur.role === "traffic") cur.role = row.role;
    byIp.set(row.ip, cur);
  }
  const tops = [...byIp.values()]
    .sort((a, b) => (b.heat - a.heat) || (b.count - a.count))
    .slice(0, 6);
  const key = tops.map((t) => `${t.ip}:${t.count}:${t.heat.toFixed(2)}`).join("|");
  if (key === topIpKey) return;
  topIpKey = key;
  host.replaceChildren();
  for (const item of tops) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "ip-chip";
    if (item.role === "botnet" || item.heat >= 0.9) btn.classList.add("hot");
    else if (item.role === "burst") btn.classList.add("burst");
    btn.title = `${item.ip} · ${item.name || item.cc || ""} · ${item.count}×`;
    const src = flagSrc(item.cc);
    if (src) {
      const img = document.createElement("img");
      img.src = src;
      img.alt = "";
      btn.appendChild(img);
    }
    const mono = document.createElement("span");
    mono.className = "mono";
    mono.textContent = item.ip;
    const strong = document.createElement("strong");
    strong.textContent = `(${item.count.toLocaleString("de-DE")})`;
    btn.append(mono, strong);
    btn.addEventListener("contextmenu", (event) => {
      event.preventDefault();
      event.stopPropagation();
      hideIpHover();
      const match = rows.find((row) => row.ip === item.ip);
      openContextMenu(event.clientX, event.clientY, match || { ip: item.ip, cc: item.cc, name: item.name });
    });
    btn.addEventListener("pointerenter", () => scheduleIpHover(btn, item.ip));
    btn.addEventListener("pointerleave", () => scheduleHideIpHover());
    btn.addEventListener("click", () => {
      state.query = item.ip;
      const box = document.getElementById("searchBox");
      if (box) box.value = item.ip;
      feed.dataset.key = "";
      savePrefs();
      const match = shown.find((row) => row.ip === item.ip);
      if (match) {
        state.picked = match;
        if (match.cc) focusCountryByCode(match.cc, { soft: true });
        loadIpLookup(match.ip);
      }
    });
    host.appendChild(btn);
  }
}

let headerKey = "";

function armDesktopNotes() {
  if (typeof Notification === "undefined" || Notification.permission !== "default") return;
  const ask = () => {
    document.removeEventListener("pointerdown", ask);
    Notification.requestPermission().catch(() => {});
  };
  document.addEventListener("pointerdown", ask);
}

function hostLine() {
  const server = state.server || {};
  const name = server.name || "Infynnite";
  const where = [server.hostname, server.ipv4].filter(Boolean).join(" / ");
  return { name, where: where ? ` (${where})` : "" };
}

function setLinkStatus(mode) {
  state.link = mode;
  const el = document.getElementById("linkStatus");
  const version = document.getElementById("brandVersion");
  if (version && state.server && state.server.version) version.textContent = state.server.version;
  if (!el) return;
  const { name, where } = hostLine();
  el.classList.remove("is-live", "is-boot", "is-down");
  if (mode === "live") {
    el.classList.add("is-live");
    el.textContent = `connected to ${name}${where}`;
    el.title = `Stream verbunden · ${name}${where}`;
  } else if (mode === "down") {
    el.classList.add("is-down");
    el.textContent = `nicht verbunden · ${name}${where}`;
    el.title = `Stream getrennt · ${name}${where}`;
  } else {
    el.classList.add("is-boot");
    el.textContent = `verbinden · ${name}${where}`;
    el.title = `Verbindung wird aufgebaut · ${name}${where}`;
  }
}

function showToast(title, sub = "", tone = "") {
  const send = () => {
    if (typeof Notification === "undefined" || Notification.permission !== "granted") return;
    try {
      const note = new Notification(title, {
        body: sub || "",
        icon: new URL("/favicon.png", location.origin).href,
        tag: tone === "hot" ? "livemap-alert" : `livemap-${title}`,
      });
      setTimeout(() => note.close(), tone === "hot" ? 8000 : 5000);
    } catch (err) { /* ignore */ }
  };
  if (typeof Notification === "undefined" || Notification.permission !== "granted") return;
  send();
}

const threatSeen = new Map();

function noticeThreat(row) {
  if (!state.follow || !row) return;
  const role = row.role || "";
  if (role !== "burst" && role !== "botnet") return;
  const now = Date.now();
  const key = `${role}|${row.ip}|${row.kind}`;
  const last = threatSeen.get(key) || 0;
  if (now - last < 45000) return;
  threatSeen.set(key, now);
  if (threatSeen.size > 200) {
    for (const [item, ts] of threatSeen) {
      if (now - ts > 120000) threatSeen.delete(item);
    }
  }
  const kind = (KIND[row.kind] || KIND.probe).label;
  const where = row.name || row.cc || row.ip || "Unbekannt";
  if (role === "botnet") showToast(`${kind} · ${where}`, row.ip || "", "hot");
  else showToast(`Burst · ${where}`, `${row.ip || ""} · ${row.burstCount || "?"}×`, "");
  const prev = document.title;
  document.title = role === "botnet" ? `⚠ ${kind} · Livemap` : `Burst · Livemap`;
  setTimeout(() => {
    if (document.title.startsWith("⚠") || document.title.startsWith("Burst")) document.title = prev;
  }, 3500);
}

function paintHeader(shown) {
  const byCc = new Map();
  for (const row of shown) {
    if (!row.cc) continue;
    const cur = byCc.get(row.cc) || { cc: row.cc, name: row.name || row.cc, count: 0 };
    cur.count += 1;
    byCc.set(row.cc, cur);
  }
  const tops = [...byCc.values()].sort((a, b) => b.count - a.count).slice(0, 5);
  const key = tops.map((t) => `${t.cc}:${t.count}`).join(",");
  if (key === headerKey) return;
  headerKey = key;
  const strip = document.getElementById("topStrip");
  if (!strip) return;
  strip.replaceChildren();
  for (const item of tops) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "top-chip";
    btn.title = `${item.name}: ${item.count}`;
    const src = flagSrc(item.cc);
    if (src) {
      const img = document.createElement("img");
      img.src = src;
      img.alt = "";
      btn.appendChild(img);
    }
    btn.append(document.createTextNode(item.cc));
    const strong = document.createElement("strong");
    strong.textContent = `(${item.count.toLocaleString("de-DE")})`;
    btn.appendChild(strong);
    btn.addEventListener("click", () => focusCountryByCode(item.cc, { soft: false }));
    strip.appendChild(btn);
  }
}

function resetMapView() {
  moveCam(0, 0, MIN_SCALE, 520);
  state.selected = null;
  const tip = document.getElementById("tip");
  if (tip) tip.hidden = true;
  const card = document.getElementById("countryCard");
  if (card) card.hidden = true;
}

function exportWindowCsv() {
  const rows = logRows(true);
  if (!rows.length) {
    showToast("Nichts zu exportieren", "Im aktuellen Fenster keine Treffer", "");
    return;
  }
  const header = ["ts", "time", "ip", "kind", "role", "cc", "country", "method", "status", "path", "bytes", "heat"];
  const lines = [header.join(",")];
  const esc = (value) => {
    const text = value == null ? "" : String(value);
    return /["',\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  };
  for (const row of rows) {
    lines.push([
      row.ts,
      formatTime(row.ts),
      row.ip,
      row.kind,
      row.role || "",
      row.cc || "",
      row.name || "",
      row.method || "",
      row.status || "",
      row.path || "",
      row.bytes || 0,
      row.heat != null ? Number(row.heat).toFixed(3) : "",
    ].map(esc).join(","));
  }
  const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  const stamp = new Date(state.cursor * 1000).toISOString().slice(0, 19).replace(/[:T]/g, "-");
  a.href = url;
  a.download = `livemap-${stamp}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  showToast("CSV exportiert", `${rows.length} Zeilen`, "ok");
}

function applyTheme(theme) {
  const next = theme === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem("livemap.theme", next); } catch (err) { /* ignore */ }
  mapLayerKey = "";
  heatStamp = 0;
  heatCam = "";
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute("content", next === "light" ? "#f3f5f7" : "#0f1216");
  document.getElementById("themeDark")?.classList.toggle("active", next === "dark");
  document.getElementById("themeLight")?.classList.toggle("active", next === "light");
}

function loadPrefs() {
  try {
    const raw = localStorage.getItem("livemap.prefs");
    if (!raw) return;
    const prefs = JSON.parse(raw);
    if (typeof prefs.role === "string") state.role = prefs.role;
    if (Array.isArray(prefs.filters)) {
      state.filters = new Set(prefs.filters.filter((id) => KIND[id]));
      if (!prefs.selfMigrated) state.filters.add("self");
    }
    if (typeof prefs.domain === "string") state.domain = prefs.domain;
    if (typeof prefs.onlyBanned === "boolean") state.onlyBanned = prefs.onlyBanned;
    if (Number.isFinite(prefs.windowSec)) state.windowSec = prefs.windowSec;
    if (Number.isFinite(prefs.speed)) state.speed = prefs.speed;
    if (typeof prefs.query === "string") state.query = prefs.query;
    if (typeof prefs.domainsCollapsed === "boolean") setDomainFold(prefs.domainsCollapsed);
    if (typeof prefs.controlsCollapsed === "boolean") setControlsFold(prefs.controlsCollapsed);
  } catch (err) { /* ignore */ }
}

function savePrefs() {
  try {
    localStorage.setItem("livemap.prefs", JSON.stringify({
      role: state.role,
      filters: [...state.filters],
      selfMigrated: true,
      domain: state.domain,
      onlyBanned: state.onlyBanned,
      windowSec: state.windowSec,
      speed: state.speed,
      query: state.query,
      domainsCollapsed: document.getElementById("domainFold")?.classList.contains("is-collapsed") || false,
      controlsCollapsed: document.body.classList.contains("controls-collapsed"),
    }));
  } catch (err) { /* ignore */ }
}

let streamSource = null;
let streamRetry = 0;

function connectStream() {
  if (streamSource) {
    try { streamSource.close(); } catch (err) { /* ignore */ }
  }
  const source = new EventSource("/api/stream");
  streamSource = source;
  source.onopen = () => {
    streamRetry = 0;
    setLinkStatus("live");
  };
  source.onmessage = (message) => {
    let ev;
    try { ev = JSON.parse(message.data); } catch (err) { return; }
    if (ev.role) {
      addHit(ev);
      noticeThreat(ev);
    } else {
      addEvent(ev);
      noticeThreat(asHit(ev));
    }
  };
  source.onerror = () => {
    setLinkStatus("down");
    try { source.close(); } catch (err) { /* ignore */ }
    streamSource = null;
    const wait = Math.min(15000, 1200 * (2 ** Math.min(4, streamRetry)));
    streamRetry += 1;
    setTimeout(connectStream, wait);
  };
}

function asHit(ev) {
  if (ev.role) return ev;
  return {
    ...ev,
    role: ATTACKS.has(ev.kind) ? "botnet" : "traffic",
    org: "",
    org_name: "",
    method: "",
    path: "",
    status: 0,
    bytes: 0,
    referer: "",
    ua: "",
    host: "",
  };
}

function isPlainVisit(row) {
  const status = Number(row.status || 0);
  return (row.kind === "page" || row.kind === "asset") && status >= 200 && status < 400;
}

function ipBurstStats(rows) {
  const byIp = new Map();
  for (const row of rows) {
    if (isPlainVisit(row)) continue;
    let bucket = byIp.get(row.ip);
    if (!bucket) {
      bucket = { count: 0, paths: new Set(), apis: 0, fails: 0, attacks: 0, first: row.ts, last: row.ts };
      byIp.set(row.ip, bucket);
    }
    bucket.count += 1;
    if (row.path) bucket.paths.add(row.path);
    if ((row.path || "").startsWith("/api/")) bucket.apis += 1;
    if ((row.status || 0) >= 400) bucket.fails += 1;
    if (ATTACKS.has(row.kind) || row.kind === "probe") bucket.attacks += 1;
    if (row.ts < bucket.first) bucket.first = row.ts;
    if (row.ts > bucket.last) bucket.last = row.ts;
  }
  return byIp;
}

function rankHit(row, burst) {
  let role = row.role || "traffic";
  let org = row.org || "";
  let org_name = row.org_name || "";
  let heat = THREAT[row.kind] ?? 0.2;
  if (isPlainVisit(row) && !ATTACKS.has(row.kind)) {
    role = role === "org" ? "org" : "traffic";
    if (org === "burst") org = "";
    if (org_name === "Burst") org_name = "";
    heat = THREAT[row.kind] ?? 0.15;
  }
  if (role === "botnet") heat = Math.max(heat, 0.9);
  if (role === "org") heat = Math.max(heat, 0.25);
  if (burst) {
    const span = Math.max(1, burst.last - burst.first);
    const rate = burst.count / span;
    const diverse = burst.paths.size >= 6 || burst.apis >= 3;
    const heavy = burst.count >= 10 && (diverse || rate >= 0.8 || burst.fails >= 4 || burst.attacks >= 2);
    const severe = burst.count >= 20 || burst.apis >= 5 || burst.fails >= 8 || burst.attacks >= 3;
    if (severe && role !== "org") {
      role = "botnet";
      org_name = org_name || "Burst";
      heat = Math.max(heat, 0.92);
    } else if (heavy && (role === "traffic" || role === "burst")) {
      role = "burst";
      org = "burst";
      org_name = "Burst";
      heat = Math.max(heat, 0.74);
    } else if (burst.count >= 6 && role === "traffic") {
      heat = Math.max(heat, 0.4 + Math.min(0.25, burst.count / 40));
    }
  }
  return {
    ...row,
    role,
    org,
    org_name,
    heat,
    burstCount: burst ? burst.count : 0,
    burstPaths: burst ? burst.paths.size : 0,
  };
}

function replaySpan() {
  return !state.follow && !!state.domain;
}

function dataStartTs() {
  const dataStart = Math.min(
    state.events.length ? state.events[0].ts : Infinity,
    state.hits.length ? state.hits[0].ts : Infinity,
  );
  return Number.isFinite(dataStart) ? dataStart : state.cursor - state.windowSec;
}

function viewFrom() {
  if (replaySpan()) return dataStartTs();
  return state.cursor - state.windowSec;
}

function rowsSince(list, from) {
  const out = [];
  for (let i = lowerBoundTs(list, from); i < list.length; i += 1) {
    const row = list[i];
    if (row.ts > state.cursor) break;
    if (!passView(row)) continue;
    out.push(row);
  }
  return out;
}

function logRows(unlimited = false) {
  const from = viewFrom();
  const hits = rowsSince(state.hits, from);
  const seen = new Set(hits.map((row) => `${row.ts}|${row.ip}|${row.kind}`));
  const attacks = rowsSince(state.events, from)
    .filter((ev) => !seen.has(`${ev.ts}|${ev.ip}|${ev.kind}`))
    .map(asHit);
  let rows = hits.concat(attacks);
  const bursts = ipBurstStats(rows);
  rows = rows.map((row) => rankHit(row, bursts.get(row.ip)));
  if (state.role === "traffic" || state.role === "botnet" || state.role === "org" || state.role === "burst") {
    rows = rows.filter((row) => row.role === state.role);
  }
  const q = (state.query || "").trim().toLowerCase();
  if (q) {
    rows = rows.filter((row) => {
      const hay = [
        row.ip, row.cc, row.name, row.path, row.host, row.method, viewKind(row), row.role, row.org_name, row.status,
        ...clientMarks(row).map((part) => part.label),
      ].map((part) => String(part || "").toLowerCase()).join(" ");
      return hay.includes(q);
    });
  }
  if (state.role === "botnet" || state.role === "burst") {
    rows.sort((a, b) => (b.heat - a.heat) || (b.ts - a.ts) || (a.ip || "").localeCompare(b.ip || ""));
  } else {
    rows.sort((a, b) => (b.ts - a.ts) || (b.heat - a.heat) || (a.ip || "").localeCompare(b.ip || ""));
  }
  if (unlimited) return rows;
  return rows.slice(0, state.role === "all" ? 180 : 220);
}

function rowLine(row) {
  const kind = (KIND[viewKind(row)] || KIND.page).label;
  const burst = row.burstCount >= 8 ? `${row.burstCount}×` : "";
  const tag = row.role === "burst" || row.org_name === "Burst" ? "Burst" : (row.org_name || "");
  const code = row.status ? String(row.status) : "";
  const method = row.method || "";
  const size = row.bytes ? formatBytes(row.bytes) : "";
  const where = [kind, method, code, tag, burst, size].filter(Boolean).join(" · ");
  const target = row.path || row.ip;
  return `${where} · ${target}`;
}

function methodTone(method) {
  const name = String(method || "").toUpperCase();
  if (name === "GET" || name === "HEAD") return "get";
  if (name === "POST") return "post";
  if (name === "PUT" || name === "PATCH") return "put";
  if (name === "DELETE") return "del";
  return "other";
}

function statusTone(code) {
  const n = Number(code);
  if (n >= 500) return "s5";
  if (n >= 400) return "s4";
  if (n >= 300) return "s3";
  if (n >= 200) return "s2";
  return "other";
}

function rowPill(text, tone) {
  const pill = document.createElement("em");
  pill.className = `pill pill-${tone}`;
  pill.textContent = text;
  return pill;
}

function fillRowMeta(meta, row) {
  const kind = (KIND[viewKind(row)] || KIND.page).label;
  const burst = row.burstCount >= 8 ? `${row.burstCount}×` : "";
  const tag = row.role === "burst" || row.org_name === "Burst" ? "Burst" : (row.org_name || "");
  const size = row.bytes ? formatBytes(row.bytes) : "";
  meta.append(document.createTextNode(kind));
  if (row.method) {
    meta.append(document.createTextNode(" · "), rowPill(row.method, methodTone(row.method)));
  }
  if (row.status) {
    meta.append(document.createTextNode(" · "), rowPill(String(row.status), statusTone(row.status)));
  }
  const rest = [tag, burst, size, row.path || row.ip].filter(Boolean);
  if (rest.length) meta.append(document.createTextNode(` · ${rest.join(" · ")}`));
}

let selfSeen = null;

function feedRowId(ev) {
  return `${ev.ts}|${ev.ip}|${ev.kind}|${ev.path || ""}`;
}

function paintFeed() {
  const rows = logRows();
  const key = rows.map(feedRowId).join("~") + "|" + state.role + "|" + state.query + "|" + state.selfIp + "|" + (state.picked && `${state.picked.ts}|${state.picked.ip}|${state.picked.path || ""}`);
  if (feed.dataset.key === key) return;
  feed.dataset.key = key;
  const prime = selfSeen == null;
  if (prime) selfSeen = new Set();
  feed.replaceChildren();
  if (!rows.length) {
    if (prime) selfSeen = null;
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = state.query ? "Keine Treffer für die Suche." : "Keine Zugriffe in diesem Fenster.";
    feed.appendChild(li);
    paintDetail();
    return;
  }
  for (const ev of rows) {
    const li = document.createElement("li");
    if (state.picked && state.picked.ts === ev.ts && state.picked.ip === ev.ip && (state.picked.path || "") === (ev.path || "")) li.classList.add("selected");
    if (ev.role === "burst") li.classList.add("burst");
    if (ev.role === "botnet" || (ev.heat || 0) >= 0.9) li.classList.add("hot");
    const self = isSelf(ev);
    const rowId = feedRowId(ev);
    if (self) {
      li.classList.add("self");
      if (!prime && !selfSeen.has(rowId) && !reduced) li.classList.add("self-in");
      selfSeen.add(rowId);
      li.title = "Eigener Client";
    } else if (state.bans.has(ev.ip)) {
      li.classList.add("banned");
      li.title = "Gesperrt";
    }
    const flag = document.createElement("img");
    flag.className = "flag";
    flag.alt = "";
    const src = flagSrc(ev.cc);
    if (src) flag.src = src;
    else flag.hidden = true;
    const mark = document.createElement("img");
    mark.className = "mark";
    mark.alt = self ? "Eigener Client" : "";
    mark.title = self ? "Eigener Client" : "";
    mark.src = markSrc(ev);
    const text = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = ev.name || ev.cc || "Unbekannt";
    const meta = document.createElement("span");
    fillRowMeta(meta, ev);
    const sub = document.createElement("span");
    sub.className = "feed-ip";
    sub.textContent = [ev.ip, ev.host].filter(Boolean).join(" · ");
    text.append(title, meta);
    if (sub.textContent) text.append(sub);
    const time = document.createElement("time");
    time.textContent = new Intl.DateTimeFormat("de-DE", {
      timeZone: "Europe/Berlin", hour: "2-digit", minute: "2-digit", second: "2-digit",
    }).format(ev.ts * 1000);
    li.append(flag, mark, text, time);
    li.addEventListener("click", (event) => {
      event.stopPropagation();
      state.picked = ev;
      if (ev.lat != null) state.selected = ev;
      if (ev.cc) focusCountryByCode(ev.cc, { soft: true });
      feed.dataset.key = "";
      loadIpLookup(ev.ip);
    });
    li.addEventListener("contextmenu", (event) => {
      event.preventDefault();
      event.stopPropagation();
      state.picked = ev;
      if (ev.lat != null) state.selected = ev;
      feed.dataset.key = "";
      hideIpHover();
      openContextMenu(event.clientX, event.clientY, ev);
    });
    if (ev.ip) {
      li.addEventListener("pointerenter", () => scheduleIpHover(li, ev.ip));
      li.addEventListener("pointerleave", () => scheduleHideIpHover());
    }
    feed.appendChild(li);
  }
  paintDetail();
}

function formatBytes(n) {
  if (!n) return "";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function threatLabel(row) {
  const score = row.heat ?? THREAT[row.kind] ?? 0.2;
  if (row.role === "botnet" || score >= 0.85) return ["Hoch", score];
  if (row.role === "burst" || score >= 0.55) return ["Auffällig", score];
  if (row.role === "org") return ["Netz", score];
  return ["Niedrig", score];
}

function ipProfile(ip) {
  let count = 0;
  let first = null;
  let last = null;
  const kinds = new Set();
  for (const ev of state.events) {
    if (ev.ip !== ip) continue;
    count += 1;
    kinds.add(ev.kind);
    if (first == null || ev.ts < first) first = ev.ts;
    if (last == null || ev.ts > last) last = ev.ts;
  }
  for (const hit of state.hits) {
    if (hit.ip !== ip) continue;
    if (first == null || hit.ts < first) first = hit.ts;
    if (last == null || hit.ts > last) last = hit.ts;
  }
  return { count, first, last, kinds: [...kinds] };
}

function whoisLabel(key) {
  return ({
    netname: "Netzname",
    "org-name": "Organisation",
    orgname: "Organisation",
    organization: "Organisation",
    org: "Organisation",
    country: "WHOIS-Land",
    origin: "ASN",
    originas: "ASN",
    cidr: "CIDR",
    inetnum: "Bereich",
    route: "Route",
    descr: "Beschreibung",
    "abuse-mailbox": "Abuse",
    orgabuseemail: "Abuse",
    address: "Adresse",
    city: "Stadt",
    stateprov: "Region",
    postalcode: "PLZ",
    phone: "Telefon",
    "mnt-by": "Maintainer",
    status: "Status",
  })[key] || key;
}

function appendLookup(box, lookup) {
  if (!lookup) return;
  const wrap = document.createElement("div");
  wrap.className = "lookup-block";
  const title = document.createElement("h3");
  title.textContent = "IP · Geo · WHOIS";
  const meta = document.createElement("dl");
  const fields = [
    ["PTR", lookup.ptr || "", "mono"],
    ["Geo", [lookup.geo?.name, lookup.geo?.cc].filter(Boolean).join(" · "), ""],
    ["Koordinaten", lookup.geo?.lat != null ? `${lookup.geo.lat}, ${lookup.geo.lon}` : "", "mono"],
    ["Bekanntes Netz", lookup.network?.name || "", ""],
    ["Gesperrt", (lookup.banned || []).length ? lookup.banned.join(", ") : "nein", ""],
  ];
  for (const [key, value] of Object.entries(lookup.whois || {})) {
    fields.push([whoisLabel(key), value, key.includes("mail") || key.includes("cidr") || key.includes("inet") ? "mono" : ""]);
  }
  for (const [label, value, cls] of fields) {
    if (!value) continue;
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    if (cls) dd.className = cls;
    dd.textContent = value;
    meta.append(dt, dd);
  }
  wrap.append(title, meta);
  const tops = document.createElement("ul");
  tops.className = "dossier-tops";
  if ((lookup.stats?.hits || []).length) {
    const head = document.createElement("li");
    head.className = "top-head";
    head.textContent = "Treffer nach Art";
    tops.appendChild(head);
    for (const item of lookup.stats.hits.slice(0, 8)) {
      const li = document.createElement("li");
      const name = document.createElement("span");
      name.textContent = `${(KIND[item.kind] || KIND.page).label} · ${roleLabel(item.role)}`;
      const value = document.createElement("span");
      value.textContent = `${item.count.toLocaleString("de-DE")}${item.bytes ? ` · ${formatBytes(item.bytes)}` : ""}`;
      li.append(name, value);
      tops.appendChild(li);
    }
  }
  if ((lookup.stats?.events || []).length) {
    const head = document.createElement("li");
    head.className = "top-head";
    head.textContent = "Sperren / Angriffe";
    tops.appendChild(head);
    for (const item of lookup.stats.events.slice(0, 6)) {
      const li = document.createElement("li");
      const name = document.createElement("span");
      name.textContent = (KIND[item.kind] || KIND.probe).label;
      const value = document.createElement("span");
      value.textContent = item.count.toLocaleString("de-DE");
      li.append(name, value);
      tops.appendChild(li);
    }
  }
  if ((lookup.stats?.paths || []).length) {
    const head = document.createElement("li");
    head.className = "top-head";
    head.textContent = "Pfade dieser IP";
    tops.appendChild(head);
    for (const item of lookup.stats.paths.slice(0, 8)) {
      const li = document.createElement("li");
      const name = document.createElement("span");
      name.className = "mono";
      name.textContent = item.path;
      const value = document.createElement("span");
      value.textContent = item.count.toLocaleString("de-DE");
      li.append(name, value);
      tops.appendChild(li);
    }
  }
  if (tops.children.length) wrap.appendChild(tops);
  if (lookup.whois_raw) {
    const pre = document.createElement("pre");
    pre.className = "whois-raw";
    pre.textContent = lookup.whois_raw.slice(0, 3200);
    wrap.appendChild(pre);
  }
  box.appendChild(wrap);
}

async function loadIpLookup(ip) {
  if (!ip || state.lookupIp === ip && state.lookup) {
    paintDetail(true);
    return;
  }
  state.lookupIp = ip;
  state.lookup = null;
  paintDetail(true);
  try {
    const res = await fetch(`/api/ip?ip=${encodeURIComponent(ip)}`);
    const data = await res.json();
    if (!res.ok || !data.ok) throw new Error(data.error || "Lookup fehlgeschlagen");
    if (state.lookupIp !== ip) return;
    state.lookup = data.lookup;
    if (data.actions != null) state.actions = !!data.actions;
    paintDetail(true);
  } catch (err) {
    if (state.lookupIp !== ip) return;
    state.lookup = { ip, error: err.message || "Lookup fehlgeschlagen" };
    paintDetail(true);
  }
}

function mapsTarget() {
  const row = state.picked;
  if (row && row.lat != null && row.lon != null) {
    return { lat: row.lat, lon: row.lon, label: row.name || row.cc || row.ip || "" };
  }
  if (state.lookup?.geo?.lat != null && state.lookupIp === row?.ip) {
    return { lat: state.lookup.geo.lat, lon: state.lookup.geo.lon, label: state.lookup.geo.name || row?.ip || "" };
  }
  if (focusItem?.bounds) {
    const b = focusItem.bounds;
    return {
      lat: (b.minLat + b.maxLat) / 2,
      lon: (b.minLon + b.maxLon) / 2,
      label: focusItem.de || focusItem.name || focusItem.cc || "",
    };
  }
  return null;
}

function openGoogleMaps(lat, lon, _label = "") {
  const y = Number(lat);
  const x = Number(lon);
  if (!Number.isFinite(y) || !Number.isFinite(x)) return false;
  // Nur reine Koordinaten – Zusatztext wie "(USA)" bricht die Maps-Suche.
  const q = `${y.toFixed(6)},${x.toFixed(6)}`;
  const url = `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(q)}`;
  const link = document.createElement("a");
  link.href = url;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.style.display = "none";
  document.body.appendChild(link);
  link.click();
  link.remove();
  return true;
}

function gmapsIcon() {
  const img = document.createElement("img");
  img.className = "gmaps-icon";
  img.src = "/marks/gmaps.svg";
  img.alt = "";
  img.width = 14;
  img.height = 14;
  return img;
}

function syncMapsBtn() {
  const btn = document.getElementById("mapsBtn");
  if (!btn) return;
  const target = mapsTarget();
  btn.disabled = !target;
  btn.title = target
    ? `Google Maps: ${target.label || `${target.lat}, ${target.lon}`}`
    : "Ort in Google Maps öffnen";
}

function mapsButton(lat, lon, label) {
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "maps-link";
  btn.append(gmapsIcon(), document.createTextNode(" Google Maps"));
  btn.disabled = lat == null || lon == null;
  btn.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();
    openGoogleMaps(lat, lon, label);
  });
  return btn;
}

function pulseCountry(cc, amount = 1) {
  if (!cc) return;
  const feature = findCountryByCode(cc);
  if (!feature) return;
  feature.flash = Math.max(feature.flash || 0, amount);
}

function setInspectCollapsed(collapsed) {
  const inspect = document.getElementById("inspect");
  const btn = document.getElementById("inspectCollapse");
  if (!inspect || !btn) return;
  inspect.classList.toggle("is-collapsed", collapsed);
  btn.title = collapsed ? "Ausklappen" : "Einklappen";
  btn.setAttribute("aria-label", btn.title);
  btn.setAttribute("aria-expanded", collapsed ? "false" : "true");
}

function settleLayout() {
  const started = performance.now();
  const tick = () => {
    resize();
    waveKey = "";
    if (performance.now() - started < 280) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

function setDomainFold(collapsed) {
  const fold = document.getElementById("domainFold");
  const btn = document.getElementById("domainFoldBtn");
  if (!fold || !btn) return;
  fold.classList.toggle("is-collapsed", collapsed);
  btn.title = collapsed ? "Domains ausklappen" : "Domains einklappen";
  btn.setAttribute("aria-label", btn.title);
  btn.setAttribute("aria-expanded", collapsed ? "false" : "true");
  const box = document.getElementById("domains");
  if (!box) return;
  if (!collapsed) {
    box.dataset.pendingHide = "";
    box.inert = false;
    return;
  }
  box.dataset.pendingHide = "1";
  setTimeout(() => {
    if (box.dataset.pendingHide === "1") box.inert = true;
  }, 230);
}

function setControlsFold(collapsed) {
  const footer = document.getElementById("controls");
  const btn = document.getElementById("controlsFold");
  if (!footer || !btn) return;
  footer.classList.toggle("is-collapsed", collapsed);
  document.body.classList.toggle("controls-collapsed", collapsed);
  for (const el of footer.querySelectorAll(".transport, .wave-wrap")) el.inert = collapsed;
  btn.title = collapsed ? "Steuerung ausklappen" : "Steuerung einklappen";
  btn.setAttribute("aria-label", btn.title);
  btn.setAttribute("aria-expanded", collapsed ? "false" : "true");
  settleLayout();
}

function showInspect() {
  const inspect = document.getElementById("inspect");
  const box = document.getElementById("detail");
  if (!inspect || !box) return;
  const opening = inspect.hidden || inspect.dataset.closing === "1" || !inspect.classList.contains("is-open");
  inspect.dataset.closing = "";
  if (window.matchMedia("(max-width: 720px)").matches && document.body.classList.contains("panel-log")) {
    setMobilePanel("map");
  }
  inspect.hidden = false;
  box.hidden = false;
  if (opening) {
    inspect.classList.remove("is-open");
    void inspect.offsetWidth;
    if (inspect.dataset.closing !== "1") inspect.classList.add("is-open");
  }
}

function hideInspect() {
  const inspect = document.getElementById("inspect");
  const box = document.getElementById("detail");
  if (!inspect || inspect.hidden || inspect.dataset.closing === "1") return;
  inspect.dataset.closing = "1";
  inspect.classList.remove("is-open");
  const finish = () => {
    if (inspect.dataset.closing !== "1") return;
    inspect.dataset.closing = "";
    inspect.hidden = true;
    setInspectCollapsed(false);
    if (box) {
      box.hidden = true;
      box.replaceChildren();
      box.dataset.key = "";
    }
  };
  const onEnd = (event) => {
    if (event.target !== inspect || event.propertyName !== "transform") return;
    inspect.removeEventListener("transitionend", onEnd);
    finish();
  };
  inspect.addEventListener("transitionend", onEnd);
  setTimeout(finish, 320);
}

function renderCountrySheet() {
  if (!focusItem) return;
  const box = document.getElementById("detail");
  if (!box) return;
  const key = `country|${focusItem.cc}|${focusItem.de || focusItem.name || ""}`;
  if (box.dataset.key !== key || box.hidden) {
    box.dataset.key = key;
    hideIpHover();
    box.replaceChildren(buildCountryDetail(focusItem.cc, focusItem.de || focusItem.name));
  }
  showInspect();
}

function paintDetail(force = false) {
  const box = document.getElementById("detail");
  const row = state.picked;
  if (!row) {
    if (focusItem) renderCountrySheet();
    else hideInspect();
    syncMapsBtn();
    return;
  }
  const stats = row.cc ? countryStats(row.cc) : null;
  const lookupKey = state.lookup && state.lookupIp === row.ip
    ? `${state.lookup.ptr || ""}|${Object.keys(state.lookup.whois || {}).length}|${(state.lookup.banned || []).join()}`
    : state.lookupIp === row.ip ? "loading" : "";
  const key = [
    row.ts, row.ip, row.path || "", row.ua || "", row.status || 0, row.cc || "",
    stats ? `${stats.session}|${stats.all}|${stats.ips}|${stats.burst}` : "",
    lookupKey,
  ].join("|");
  if (!force && box.dataset.key === key && !box.hidden) {
    showInspect();
    return;
  }
  box.dataset.key = key;
  hideIpHover();
  showInspect();
  box.replaceChildren();
  if (row.cc) box.append(buildCountryDetail(row.cc, row.name));
  const packet = document.createElement("div");
  packet.className = "packet-block";
  const title = document.createElement("h3");
  const mark = document.createElement("img");
  mark.className = "mark";
  mark.alt = "";
  mark.src = markSrc(row);
  const headline = row.role === "burst" ? "Auffälliger Burst"
    : row.role === "botnet" ? (row.org_name === "Burst" ? "Schwerer Burst" : "Botnetz")
    : row.kind === "page" || row.kind === "asset" ? "Webzugriff"
    : (row.org_name || "Paket");
  title.append(mark, document.createTextNode(headline));
  const marks = clientMarks(row);
  for (const part of marks) {
    const osMark = document.createElement("img");
    osMark.className = "mark";
    osMark.alt = part.label;
    osMark.title = part.label;
    osMark.src = part.icon;
    title.append(osMark);
  }
  const [level, score] = threatLabel(row);
  const threat = document.createElement("p");
  threat.className = "threat";
  const burstInfo = row.burstCount ? ` · ${row.burstCount} Zugriffe / ${row.burstPaths || 0} Pfade` : "";
  threat.innerHTML = `Verdacht <strong>${level}</strong> · ${(score * 100).toFixed(0)}${burstInfo}`;
  const profile = ipProfile(row.ip);
  const list = document.createElement("dl");
  const fields = [
    ["Zeit", formatTime(row.ts), ""],
    ["Paket", `${row.method || "–"} ${row.path || ""}`.trim(), "mono"],
    ["Adresse", row.ip, "mono"],
    ["System", osLine(marks), "os"],
    ["Art", (KIND[row.kind] || KIND.page).label, ""],
    ["Status", row.status ? String(row.status) : "", "mono"],
    ["Bytes", formatBytes(row.bytes), "mono"],
    ["Host", row.host || "", "mono"],
    ["Referer", row.referer || "", "mono"],
    ["Client", row.ua || "", ""],
    ["Netz", row.org_name || row.org || "", ""],
    ["Koordinaten", row.lat != null ? `${row.lat}, ${row.lon}` : "", "mono"],
    ["Von IP", profile.count ? `${profile.count} Treffer · ${profile.kinds.map((k) => (KIND[k] || KIND.page).label).join(", ")}` : "", ""],
    ["Erster", profile.first ? formatTime(profile.first) : "", ""],
    ["Letzter", profile.last ? formatTime(profile.last) : "", ""],
  ];
  for (const [label, value, cls] of fields) {
    if (!value) continue;
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    if (cls) dd.className = cls;
    if (value instanceof Node) dd.append(value);
    else dd.textContent = value;
    list.append(dt, dd);
  }
  const actions = document.createElement("div");
  actions.className = "detail-actions";
  const lat = row.lat ?? state.lookup?.geo?.lat;
  const lon = row.lon ?? state.lookup?.geo?.lon;
  actions.append(mapsButton(lat, lon, row.name || row.cc || row.ip || ""));
  packet.append(title, threat, list, actions);
  box.append(packet);
  if (state.lookupIp === row.ip && state.lookup) {
    if (state.lookup.error) {
      const note = document.createElement("p");
      note.className = "threat";
      note.textContent = state.lookup.error;
      box.appendChild(note);
    } else appendLookup(box, state.lookup);
  } else if (state.lookupIp === row.ip) {
    const note = document.createElement("p");
    note.className = "threat";
    note.textContent = "WHOIS und Geo werden geladen …";
    box.appendChild(note);
  }
  syncMapsBtn();
}

function syncScrub() {}

function syncLive() {
  const live = state.follow;
  document.getElementById("liveBtn").classList.toggle("solid", live);
  document.getElementById("liveBtn").classList.toggle("is-live", live);
  document.getElementById("controls").classList.toggle("live", live);
  document.body.classList.toggle("live-mode", live);
}

function syncPlay() {
  const playing = state.playing && !state.follow;
  const playBtn = document.getElementById("playBtn");
  const label = document.getElementById("playLabel");
  playBtn.classList.toggle("solid", playing);
  playBtn.classList.toggle("is-playing", playing);
  if (label) label.textContent = playing ? "Pause" : "Replay";
}

function addHit(row) {
  const last = state.hits[state.hits.length - 1];
  if (!last || row.ts >= last.ts) state.hits.push(row);
  else {
    const index = state.hits.findIndex((item) => item.ts > row.ts);
    state.hits.splice(index < 0 ? state.hits.length : index, 0, row);
  }
  if (state.hits.length > 5000) state.hits.splice(0, state.hits.length - 5000);
  trimFlightDone();
  if (flight.primed && state.follow && row.lat != null && passView(row)) enqueueFlight(row);
}

function trimFlightDone() {
  if (flight.done.size < 8000) return;
  const cutoff = state.cursor - Math.max(state.windowSec, 3600);
  for (const key of flight.done) {
    if (Number(key.slice(0, key.indexOf("|"))) < cutoff) flight.done.delete(key);
  }
}

function addEvent(ev) {
  const last = state.events[state.events.length - 1];
  if (last && ev.ts >= last.ts) state.events.push(ev);
  else {
    const i = state.events.findIndex((item) => item.ts > ev.ts);
    state.events.splice(i < 0 ? state.events.length : i, 0, ev);
  }
  if (state.events.length > 4000) state.events.splice(0, state.events.length - 4000);
  trimFlightDone();
  if (flight.primed && state.follow && ev.lat != null && passView(ev)) enqueueFlight(ev);
}

function buildControls() {
  const roles = document.getElementById("roles");
  for (const [id, label] of ROLES) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = label;
    if (id === state.role) btn.classList.add("active");
    btn.addEventListener("click", () => {
      state.role = id;
      for (const child of roles.children) child.classList.remove("active");
      btn.classList.add("active");
      feed.dataset.key = "";
      savePrefs();
    });
    roles.appendChild(btn);
  }
  const banBtn = document.createElement("button");
  banBtn.type = "button";
  banBtn.id = "banToggle";
  banBtn.textContent = "Gebannt";
  banBtn.classList.toggle("active", state.onlyBanned);
  banBtn.addEventListener("click", () => {
    state.onlyBanned = !state.onlyBanned;
    banBtn.classList.toggle("active", state.onlyBanned);
    waveKey = "";
    resetFlights();
    feed.dataset.key = "";
    savePrefs();
  });
  roles.appendChild(banBtn);
  const filters = document.getElementById("filters");
  for (const [id, label, color] of KINDS) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = label;
    btn.classList.toggle("active", state.filters.has(id));
    btn.addEventListener("click", () => {
      if (state.filters.has(id)) state.filters.delete(id);
      else state.filters.add(id);
      btn.classList.toggle("active", state.filters.has(id));
      waveKey = "";
      resetFlights();
      feed.dataset.key = "";
      savePrefs();
    });
    filters.appendChild(btn);
  }
  const speeds = document.getElementById("speeds");
  for (const [value, label] of SPEEDS) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = label;
    if (value === state.speed) btn.classList.add("active");
    btn.addEventListener("click", () => {
      state.speed = value;
      for (const child of speeds.children) child.classList.remove("active");
      btn.classList.add("active");
      savePrefs();
    });
    speeds.appendChild(btn);
  }
  const windows = document.getElementById("windows");
  for (const [value, label] of WINDOWS) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = label;
    if (value === state.windowSec) btn.classList.add("active");
    btn.addEventListener("click", () => {
      state.windowSec = value;
      state.waveZoom = 1;
      resetFlights();
      for (const child of windows.children) child.classList.remove("active");
      btn.classList.add("active");
      waveKey = "";
      feed.dataset.key = "";
      savePrefs();
    });
    windows.appendChild(btn);
  }
  const search = document.getElementById("searchBox");
  if (search) {
    search.value = state.query || "";
    let timer = 0;
    search.addEventListener("input", () => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        state.query = search.value.trim();
        feed.dataset.key = "";
        topIpKey = "";
        savePrefs();
      }, 120);
    });
  }
}

document.getElementById("liveBtn").addEventListener("click", () => {
  if (state.follow) return;
  state.waveZoom = 1;
  state.follow = true;
  state.playing = false;
  const full = timeRange();
  startWaveFlight(Math.min(full.span, LIVE_SPAN), true);
  state.cursor = Math.max(latestTs(), Date.now() / 1000);
  resetFlights();
  syncLive();
  syncPlay();
  feed.dataset.key = "";
});

document.getElementById("playBtn").addEventListener("click", () => {
  const wasLive = state.follow;
  if (wasLive) {
    const full = timeRange();
    startWaveFlight(Math.max(8, full.span), false);
  }
  state.follow = false;
  if (wasLive) state.playing = true;
  else state.playing = !state.playing;
  let restarted = false;
  if (state.playing && state.cursor >= latestTs() - 1) {
    state.cursor = earliestTs();
    state.born.clear();
    restarted = true;
  }
  if (wasLive || restarted) resetFlights();
  syncLive();
  syncPlay();
});

let draggingWave = false;
let waveDragDist = 0;
let waveDownX = 0;
let waveWasPlaying = false;
wave.addEventListener("pointerdown", (event) => {
  if (event.button !== 0) return;
  draggingWave = true;
  waveDragDist = 0;
  waveDownX = event.clientX;
  waveWasPlaying = state.playing && !state.follow;
  if (!state.follow) seekWave(event.clientX, { pause: true });
  try { wave.setPointerCapture(event.pointerId); } catch (err) { /* synthetic events */ }
});
wave.addEventListener("pointermove", (event) => {
  if (!draggingWave) return;
  waveDragDist += Math.abs(event.clientX - waveDownX);
  waveDownX = event.clientX;
  if (state.follow && waveDragDist < 6) return;
  seekWave(event.clientX, { pause: true });
});
wave.addEventListener("pointerup", (event) => {
  if (!draggingWave) return;
  draggingWave = false;
  if (waveDragDist < 6) {
    if (!state.follow) seekWave(event.clientX, { pause: true, play: !waveWasPlaying });
  }
});
wave.addEventListener("pointercancel", () => {
  draggingWave = false;
});
wave.addEventListener("contextmenu", (event) => {
  event.preventDefault();
  const hit = binAtClientX(event.clientX);
  if (!hit) return;
  openStarMenu(event.clientX, event.clientY, hit.ts);
});
wave.parentElement?.addEventListener("pointermove", (event) => {
  const hit = binAtClientX(event.clientX);
  waveHover = hit ? hit.index : -1;
});
wave.parentElement?.addEventListener("pointerleave", () => {
  waveHover = -1;
});
wave.addEventListener("wheel", (event) => {
  event.preventDefault();
  const rect = wave.getBoundingClientRect();
  const horizontal = Math.abs(event.deltaX) > Math.abs(event.deltaY) || event.shiftKey;
  if (horizontal) {
    const delta = event.shiftKey ? event.deltaY : event.deltaX;
    panWave(delta, rect.width);
    return;
  }
  // Nach oben = reinzoomen, nach unten = rauszoomen (wie auf der Karte).
  const factor = Math.exp(-event.deltaY * 0.0018);
  if (state.follow) {
    event.preventDefault();
    return;
  }
  const ratio = Math.min(1, Math.max(0, (event.clientX - rect.left) / rect.width));
  const view = waveView();
  const anchor = view.start + view.span * ratio;
  state.waveZoom *= factor;
  waveFlight = null;
  const nextSpan = targetWaveSpan(timeRange());
  waveSpanShown = nextSpan;
  state.waveOrigin = anchor - nextSpan * ratio;
  waveView();
  waveKey = "";
}, { passive: false });

function prepareCountry(feature) {
  const name = feature.properties.name;
  const meta = GEO[name] || ["", name];
  return {
    geometry: feature.geometry,
    name,
    cc: meta[0],
    de: meta[1],
    bounds: featureBounds(feature.geometry),
    edge: 0,
    flash: 0,
  };
}

function featureBounds(geometry) {
  const polys = geometry.type === "Polygon" ? [geometry.coordinates] : geometry.coordinates;
  let best = null;
  for (const poly of polys) {
    const ring = poly[0];
    if (!ring || !ring.length) continue;
    let minLon = 180;
    let maxLon = -180;
    let minLat = 90;
    let maxLat = -90;
    for (const [lon, lat] of ring) {
      minLon = Math.min(minLon, lon);
      maxLon = Math.max(maxLon, lon);
      minLat = Math.min(minLat, lat);
      maxLat = Math.max(maxLat, lat);
    }
    if (maxLon - minLon > 180) continue;
    const area = (maxLon - minLon) * (maxLat - minLat);
    if (!best || area > best.area) best = { minLon, maxLon, minLat, maxLat, area };
  }
  return best;
}

function ringHit(lon, lat, ring) {
  let inside = false;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const xi = ring[i][0];
    const yi = ring[i][1];
    const xj = ring[j][0];
    const yj = ring[j][1];
    if ((yi > lat) !== (yj > lat) && lon < ((xj - xi) * (lat - yi)) / (yj - yi) + xi) inside = !inside;
  }
  return inside;
}

function hitCountry(lon, lat) {
  let found = null;
  let area = Infinity;
  for (const feature of state.features) {
    const bounds = feature.bounds;
    if (bounds && (lon < bounds.minLon || lon > bounds.maxLon || lat < bounds.minLat || lat > bounds.maxLat)) continue;
    const polys = feature.geometry.type === "Polygon" ? [feature.geometry.coordinates] : feature.geometry.coordinates;
    for (const poly of polys) {
      if (!ringHit(lon, lat, poly[0])) continue;
      const size = bounds ? bounds.area : 0;
      if (size < area) {
        area = size;
        found = feature;
      }
      break;
    }
  }
  return found;
}

function countryStats(cc) {
  const from = state.cursor - state.windowSec;
  const hourFrom = state.cursor - 3600;
  const kinds = {};
  const roles = {};
  const ipCounts = {};
  const pathCounts = {};
  const orgCounts = new Map();
  let session = 0;
  let hour = 0;
  let all = 0;
  let bytes = 0;
  let burst = 0;
  let first = null;
  let last = null;
  if (!cc) {
    return {
      session, hour, all, ips: 0, kinds, roles, topIps: [], topPaths: [], topOrgs: [],
      bytes, burst, first, last, win: session,
    };
  }
  const seen = new Set();
  const absorb = (row, isHit) => {
    if (row.cc !== cc || !passView(row)) return;
    const key = `${row.ts}|${row.ip}|${row.kind}|${row.path || ""}`;
    if (seen.has(key)) return;
    seen.add(key);
    all += 1;
    if (first == null || row.ts < first) first = row.ts;
    if (last == null || row.ts > last) last = row.ts;
    if (row.ts >= hourFrom && row.ts <= state.cursor) hour += 1;
    if (row.ts < from || row.ts > state.cursor) return;
    session += 1;
    kinds[row.kind] = (kinds[row.kind] || 0) + 1;
    if (row.ip) ipCounts[row.ip] = (ipCounts[row.ip] || 0) + 1;
    if (row.path) pathCounts[row.path] = (pathCounts[row.path] || 0) + 1;
    if (row.bytes) bytes += Number(row.bytes) || 0;
    if (isHit) {
      const role = row.role || "traffic";
      roles[role] = (roles[role] || 0) + 1;
      if (role === "burst" || role === "botnet") burst += row.burstCount || 1;
      if (row.org_name || row.org) {
        const name = row.org_name || row.org;
        const cur = orgCounts.get(name) || { name, key: row.org || "", count: 0 };
        cur.count += 1;
        if (row.org) cur.key = row.org;
        orgCounts.set(name, cur);
      }
    }
  };
  for (const hit of state.hits) absorb(hit, true);
  for (const ev of state.events) absorb(ev, false);
  const top = (map, n = 4) => Object.entries(map).sort((a, b) => b[1] - a[1]).slice(0, n);
  return {
    session,
    hour,
    all,
    ips: Object.keys(ipCounts).length,
    kinds,
    roles,
    topIps: top(ipCounts),
    topPaths: top(pathCounts),
    topOrgs: [...orgCounts.values()].sort((a, b) => b.count - a.count).slice(0, 3),
    bytes,
    burst,
    first,
    last,
    win: session,
  };
}

function roleLabel(role) {
  return ({ traffic: "Verkehr", burst: "Auffällig", botnet: "Botnetz", org: "Netze", all: "Alles" })[role] || role;
}

function fillMetaList(node, rows) {
  node.replaceChildren();
  for (const [label, value] of rows) {
    if (!value && value !== 0) continue;
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = typeof value === "number" ? value.toLocaleString("de-DE") : value;
    node.append(dt, dd);
  }
}

function orgIcon(key) {
  const slug = String(key || "").trim().toLowerCase().replace(/[^a-z0-9]+/g, "");
  return slug ? `/marks/${slug}.svg` : "";
}

function fillTopList(node, sections) {
  node.replaceChildren();
  for (const [heading, rows, mode] of sections) {
    if (!rows.length) continue;
    const head = document.createElement("li");
    head.className = "top-head";
    head.textContent = heading;
    node.appendChild(head);
    for (const row of rows) {
      const label = Array.isArray(row) ? row[0] : row.name;
      const count = Array.isArray(row) ? row[1] : row.count;
      const li = document.createElement("li");
      const name = document.createElement("span");
      name.className = mode === "ip" || mode === "path" ? "mono top-label" : "top-label";
      if (mode === "org") {
        const src = orgIcon(row.key || label);
        if (src) {
          const img = document.createElement("img");
          img.className = "org-mark";
          img.alt = "";
          img.src = src;
          img.addEventListener("error", () => img.remove());
          name.appendChild(img);
        }
      }
      name.append(document.createTextNode(label));
      const value = document.createElement("span");
      value.textContent = count.toLocaleString("de-DE");
      li.append(name, value);
      if (mode === "ip") bindIpLine(li, label);
      node.appendChild(li);
    }
  }
}

function buildCountryDetail(cc, name) {
  const stats = countryStats(cc);
  const wrap = document.createElement("div");
  wrap.className = "country-dossier";
  const head = document.createElement("h3");
  setLabeled(head, name || cc || "Unbekannt", cc);
  const figures = document.createElement("p");
  figures.className = "dossier-figures";
  figures.innerHTML = `<strong>${stats.session.toLocaleString("de-DE")}</strong> in dieser Session · <strong>${stats.all.toLocaleString("de-DE")}</strong> insgesamt · <strong>${stats.ips.toLocaleString("de-DE")}</strong> Adressen`;
  const meta = document.createElement("dl");
  meta.className = "dossier-meta";
  const roleBits = Object.entries(stats.roles).sort((a, b) => b[1] - a[1]).slice(0, 4)
    .map(([role, count]) => `${roleLabel(role)} ${count}`).join(" · ");
  fillMetaList(meta, [
    ["Stunde", stats.hour ? `${stats.hour.toLocaleString("de-DE")} Treffer` : ""],
    ["Bytes", stats.bytes ? formatBytes(stats.bytes) : ""],
    ["Bursts", stats.burst ? `${stats.burst.toLocaleString("de-DE")} Zugriffe` : ""],
    ["Rollen", roleBits],
    ["Erster", stats.first ? formatTime(stats.first) : ""],
    ["Letzter", stats.last ? formatTime(stats.last) : ""],
  ]);
  const kinds = document.createElement("ul");
  kinds.className = "dossier-kinds";
  const kindRows = Object.entries(stats.kinds).sort((a, b) => b[1] - a[1]);
  if (!kindRows.length) {
    const li = document.createElement("li");
    li.textContent = "Keine Treffer in dieser Session.";
    kinds.appendChild(li);
  } else {
    for (const [kind, count] of kindRows) {
      const li = document.createElement("li");
      const label = document.createElement("span");
      label.textContent = (KIND[kind] || KIND.probe).label;
      const value = document.createElement("span");
      value.textContent = count.toLocaleString("de-DE");
      li.append(label, value);
      kinds.appendChild(li);
    }
  }
  const tops = document.createElement("ul");
  tops.className = "dossier-tops";
  fillTopList(tops, [
    ["Häufigste Adressen", stats.topIps, "ip"],
    ["Häufigste Pfade", stats.topPaths, "path"],
    ["Netze", stats.topOrgs, "org"],
  ]);
  wrap.append(head, figures, meta, kinds, tops);
  return wrap;
}

function paintTip(feature) {
  const stats = countryStats(feature.cc);
  const kinds = Object.entries(stats.kinds).sort((a, b) => b[1] - a[1]).slice(0, 4);
  tip.replaceChildren();
  const src = flagSrc(feature.cc);
  if (src) {
    const img = document.createElement("img");
    img.className = "tip-flag";
    img.alt = "";
    img.src = src;
    tip.append(img);
  }
  const title = document.createElement("strong");
  title.textContent = feature.de || feature.name || "Unbekannt";
  tip.append(title);
  const lines = [
    ["tip-meta", `${stats.session.toLocaleString("de-DE")} in dieser Session`],
    ["tip-meta", `${stats.all.toLocaleString("de-DE")} insgesamt · ${stats.hour.toLocaleString("de-DE")} in der Stunde`],
    ["tip-meta", `${stats.ips.toLocaleString("de-DE")} Adressen`],
  ];
  if (kinds.length) {
    lines.push(["tip-kinds", kinds.map(([kind, count]) => `${(KIND[kind] || KIND.probe).label} ${count}`).join(" · ")]);
  } else if (!stats.all) {
    lines.push(["tip-kinds", "Keine Treffer"]);
  }
  for (const [cls, text] of lines) {
    const line = document.createElement("div");
    line.className = cls;
    line.textContent = text;
    tip.append(line);
  }
}

function paintCountry() {
  if (!focusItem) return;
  const stats = countryStats(focusItem.cc);
  setLabeled(document.getElementById("countryName"), focusItem.de || focusItem.name, focusItem.cc);
  document.getElementById("countryWin").textContent = stats.win.toLocaleString("de-DE");
  document.getElementById("countryAll").textContent = stats.all.toLocaleString("de-DE");
  const meta = document.getElementById("countryMeta");
  const list = document.getElementById("countryKinds");
  const tops = document.getElementById("countryTops");
  const roleBits = Object.entries(stats.roles).sort((a, b) => b[1] - a[1]).slice(0, 3)
    .map(([role, count]) => `${roleLabel(role)} ${count}`).join(" · ");
  const key = [
    focusItem.cc, stats.session, stats.all, stats.ips, stats.hour, stats.burst, stats.bytes,
    Object.entries(stats.kinds).map(([k, v]) => `${k}${v}`).join(),
    stats.topIps.map(([ip, n]) => `${ip}${n}`).join(),
    stats.topPaths.map(([p, n]) => `${p}${n}`).join(),
  ].join("|");
  if (list.dataset.key === key) return;
  list.dataset.key = key;
  fillMetaList(meta, [
    ["Adressen", stats.ips],
    ["Stunde", stats.hour],
    ["Bytes", stats.bytes ? formatBytes(stats.bytes) : ""],
    ["Bursts", stats.burst || ""],
    ["Rollen", roleBits],
    ["Zeitraum", stats.first && stats.last ? `${formatTime(stats.first)} – ${formatTime(stats.last)}` : ""],
  ]);
  list.replaceChildren();
  const rows = Object.entries(stats.kinds).sort((a, b) => b[1] - a[1]);
  if (!rows.length) {
    const li = document.createElement("li");
    li.textContent = "Keine Treffer in dieser Session.";
    list.appendChild(li);
  } else {
    for (const [kind, count] of rows) {
      const li = document.createElement("li");
      const label = document.createElement("span");
      label.textContent = (KIND[kind] || KIND.probe).label;
      const value = document.createElement("span");
      value.textContent = count.toLocaleString("de-DE");
      li.append(label, value);
      list.appendChild(li);
    }
  }
  fillTopList(tops, [
    ["Top-Adressen", stats.topIps.slice(0, 3), "ip"],
    ["Top-Pfade", stats.topPaths.slice(0, 3), "path"],
    ["Netze", stats.topOrgs.slice(0, 3), "org"],
  ]);
  syncMapsBtn();
}

function findCountryByCode(cc) {
  if (!cc) return null;
  return state.features.find((feature) => feature.cc === cc) || null;
}

function countryScale(bounds, soft) {
  const pad = soft ? 1.45 : 1.08;
  const lonSpan = Math.max(soft ? 8 : 3.5, (bounds.maxLon - bounds.minLon) * pad);
  const latSpan = Math.max(soft ? 6 : 2.5, (bounds.maxLat - bounds.minLat) * pad);
  const fitted = 1 / Math.max(lonSpan / 360, latSpan / 180);
  return soft
    ? Math.min(10, Math.max(2, fitted))
    : Math.min(MAX_SCALE, Math.max(2.8, fitted));
}

function focusCountry(feature, options = {}) {
  if (!feature || !feature.bounds) return;
  const soft = !!options.soft;
  const bounds = feature.bounds;
  focusItem = feature;
  moveCam(
    (bounds.minLon + bounds.maxLon) / 2,
    (bounds.minLat + bounds.maxLat) / 2,
    countryScale(bounds, soft),
  );
  if (!state.picked) renderCountrySheet();
  else showInspect();
  syncMapsBtn();
}

function unprojectPose(x, y, box, pose) {
  const cx = (pose.lon + 180) / 360;
  const cy = (90 - pose.lat) / 180;
  const wx = (x - box.x - box.w / 2) / (box.w * pose.scale) + cx;
  const wy = (y - box.y - box.h / 2) / (box.h * pose.scale) + cy;
  return [wx * 360 - 180, 90 - wy * 180];
}

function zoomMapAt(clientX, clientY, factor, options = {}) {
  const animate = options.animate !== false;
  const rect = canvas.getBoundingClientRect();
  const x = (clientX - rect.left) * (canvas.width / rect.width);
  const y = (clientY - rect.top) * (canvas.height / rect.height);
  const box = mapBox;
  const base = {
    lon: camAnim ? camTarget.lon : cam.lon,
    lat: camAnim ? camTarget.lat : cam.lat,
    scale: camAnim ? camTarget.scale : cam.scale,
  };
  const next = Math.min(MAX_SCALE, Math.max(MIN_SCALE, base.scale * factor));
  if (Math.abs(next - base.scale) < 0.0005) return;
  const [lon, lat] = unprojectPose(x, y, box, base);
  const wx = (lon + 180) / 360;
  const wy = (90 - lat) / 180;
  const cx = wx - (x - box.x - box.w / 2) / (box.w * next);
  const cy = wy - (y - box.y - box.h / 2) / (box.h * next);
  let nextLon = cx * 360 - 180;
  let nextLat = 90 - cy * 180;
  nextLon = ((nextLon + 540) % 360) - 180;
  nextLat = Math.max(-80, Math.min(80, nextLat));
  if (next <= 1.02) {
    if (focusItem) closeCountry();
    else if (animate) moveCam(0, 0, 1, 240);
    else setCam(0, 0, 1);
    return;
  }
  if (animate) moveCam(nextLon, nextLat, next, 240);
  else setCam(nextLon, nextLat, next);
}

function panMapBy(dxCss, dyCss) {
  if (!mapBox || !mapBox.w) return;
  const rect = canvas.getBoundingClientRect();
  const dx = dxCss * (canvas.width / Math.max(1, rect.width));
  const dy = dyCss * (canvas.height / Math.max(1, rect.height));
  const dLon = -(dx / (mapBox.w * cam.scale)) * 360;
  const dLat = (dy / (mapBox.h * cam.scale)) * 180;
  setCam(cam.lon + dLon, cam.lat + dLat, cam.scale);
}

function focusCountryByCode(cc, options = {}) {
  const feature = findCountryByCode(cc);
  if (feature) focusCountry(feature, options);
}

function clearSelection() {
  state.picked = null;
  state.selected = null;
  state.lookup = null;
  state.lookupIp = "";
  feed.dataset.key = "";
  if (!focusItem) hideInspect();
  paintFeed();
  syncMapsBtn();
}

function closeCountry() {
  focusItem = null;
  clearSelection();
  moveCam(0, 0, 1);
  const card = document.getElementById("countryCard");
  card.classList.remove("open");
  setTimeout(() => {
    if (!focusItem) card.hidden = true;
  }, 280);
}

const tip = document.getElementById("tip");
let panDrag = null;
let suppressClick = false;

function endPan(event) {
  if (!panDrag) return;
  if (event && panDrag.pointerId != null) {
    try { canvas.releasePointerCapture(panDrag.pointerId); } catch (err) { /* ignore */ }
  }
  panDrag = null;
  canvas.classList.remove("panning");
  canvas.style.cursor = hoverItem ? "pointer" : "default";
}

canvas.addEventListener("pointerdown", (event) => {
  if (event.button !== 1) return;
  event.preventDefault();
  suppressClick = true;
  panDrag = { x: event.clientX, y: event.clientY, pointerId: event.pointerId, moved: false };
  canvas.classList.add("panning");
  canvas.style.cursor = "grabbing";
  tip.classList.remove("show");
  try { canvas.setPointerCapture(event.pointerId); } catch (err) { /* ignore */ }
});
canvas.addEventListener("pointermove", (event) => {
  if (panDrag) {
    const dx = event.clientX - panDrag.x;
    const dy = event.clientY - panDrag.y;
    if (dx || dy) {
      panDrag.moved = true;
      panMapBy(dx, dy);
      panDrag.x = event.clientX;
      panDrag.y = event.clientY;
    }
    tip.classList.remove("show");
    return;
  }
  const rect = canvas.getBoundingClientRect();
  const x = (event.clientX - rect.left) * (canvas.width / rect.width);
  const y = (event.clientY - rect.top) * (canvas.height / rect.height);
  const [lon, lat] = unproject(x, y, mapBox);
  hoverItem = hitCountry(lon, lat);
  canvas.style.cursor = hoverItem ? "pointer" : "default";
  if (!hoverItem) {
    tip.classList.remove("show");
    return;
  }
  tip.hidden = false;
  paintTip(hoverItem);
  const stage = canvas.parentElement.getBoundingClientRect();
  tip.style.left = `${event.clientX - stage.left}px`;
  tip.style.top = `${event.clientY - stage.top}px`;
  requestAnimationFrame(() => tip.classList.add("show"));
});
canvas.addEventListener("pointerup", endPan);
canvas.addEventListener("pointercancel", endPan);
canvas.addEventListener("pointerleave", () => {
  if (panDrag) return;
  hoverItem = null;
  canvas.style.cursor = "default";
  tip.classList.remove("show");
});
canvas.addEventListener("auxclick", (event) => {
  if (event.button === 1) event.preventDefault();
});
canvas.parentElement.addEventListener("click", (event) => {
  if (suppressClick) {
    suppressClick = false;
    return;
  }
  if (event.target === canvas && hoverItem) {
    if (hoverItem !== focusItem) focusCountry(hoverItem, { soft: false });
    else zoomMapAt(event.clientX, event.clientY, 1.55, { animate: true });
    return;
  }
  if (focusItem && event.target === canvas) closeCountry();
});
canvas.addEventListener("wheel", (event) => {
  event.preventDefault();
  let dy = event.deltaY;
  if (event.deltaMode === 1) dy *= 16;
  else if (event.deltaMode === 2) dy *= Math.max(1, canvas.clientHeight);
  dy = Math.max(-80, Math.min(80, dy));
  const factor = Math.exp(-dy * 0.0022);
  zoomMapAt(event.clientX, event.clientY, factor);
}, { passive: false });
addEventListener("keydown", (event) => {
  if (event.key === "Escape" && focusItem) closeCountry();
});

addEventListener("resize", resize);
loadPrefs();
loadStars();
applyTheme(localStorage.getItem("livemap.theme"));
document.querySelectorAll("[data-theme-pick]").forEach((button) => {
  button.addEventListener("click", () => applyTheme(button.dataset.themePick));
});
buildControls();
syncLive();
syncPlay();
syncMapsBtn();

document.getElementById("mapsBtn")?.addEventListener("click", () => {
  const target = mapsTarget();
  if (!target) return;
  openGoogleMaps(target.lat, target.lon, target.label);
});
document.getElementById("countryMapsBtn")?.addEventListener("click", (event) => {
  event.stopPropagation();
  const target = mapsTarget();
  if (!target) return;
  openGoogleMaps(target.lat, target.lon, target.label);
});

function copyText(text) {
  if (!text) return;
  if (navigator.clipboard?.writeText) navigator.clipboard.writeText(text).catch(() => {});
  else {
    const area = document.createElement("textarea");
    area.value = text;
    document.body.appendChild(area);
    area.select();
    try { document.execCommand("copy"); } catch (err) { /* ignore */ }
    area.remove();
  }
  showToast("Kopiert", text, "ok");
}

async function runRowAction(id, row) {
  if (!row) return;
  try {
    if (id === "details") {
      state.picked = row;
      feed.dataset.key = "";
      await loadIpLookup(row.ip);
    } else if (id === "copy-ip") copyText(row.ip);
    else if (id === "copy-path") copyText(row.path || "");
    else if (id === "copy-line") copyText(`${formatTime(row.ts)} ${row.ip} ${row.method || ""} ${row.path || ""} ${row.status || ""}`.trim());
    else if (id === "focus" && row.cc) focusCountryByCode(row.cc, { soft: false });
    else if (id === "maps") openGoogleMaps(row.lat, row.lon, row.name || row.cc || row.ip || "");
    else if (id === "ext-abuse") open(`https://www.abuseipdb.com/check/${encodeURIComponent(row.ip)}`, "_blank", "noopener");
    else if (id === "ext-vt") open(`https://www.virustotal.com/gui/ip-address/${encodeURIComponent(row.ip)}`, "_blank", "noopener");
    else if (id === "ext-info") open(`https://ipinfo.io/${encodeURIComponent(row.ip)}`, "_blank", "noopener");
    else if (id === "ext-bgp") open(`https://bgp.he.net/ip/${encodeURIComponent(row.ip)}`, "_blank", "noopener");
    else if (id === "block") {
      const done = [];
      let lastErr = null;
      for (const jail of state.jails) {
        try {
          await runIpAction("ban", row.ip, jail);
          done.push(jail);
        } catch (err) {
          lastErr = err;
        }
      }
      if (!done.length) throw lastErr || new Error("Blocken fehlgeschlagen");
      showToast("IP blockiert", `${row.ip} · ${done.join(", ")}`, "hot");
    } else if (id === "unban") {
      for (const jail of state.jails) {
        try { await runIpAction("unban", row.ip, jail); } catch (err) { /* jail may not contain ip */ }
      }
      showToast("Entsperrt", row.ip, "ok");
    }
  } catch (err) {
    alert(err.message || "Aktion fehlgeschlagen");
  }
}

function closeContextMenu() {
  const menu = document.getElementById("ctx");
  if (!menu) return;
  menu.hidden = true;
  menu.replaceChildren();
}

async function runIpAction(op, ip, jail) {
  const res = await fetch("/api/action", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ op, ip, jail }),
  });
  const data = await res.json();
  if (!res.ok || !data.ok) throw new Error(data.error || data.output || "Aktion fehlgeschlagen");
  if (Array.isArray(data.banned)) {
    if (data.banned.length) state.bans.set(ip, data.banned);
    else state.bans.delete(ip);
    state.banRev += 1;
    paintBanButton();
  }
  if (state.lookup && state.lookupIp === ip) {
    state.lookup = { ...state.lookup, banned: data.banned || [] };
    paintDetail(true);
  }
  return data;
}

let domainKey = "";

function paintBanButton() {
  const btn = document.getElementById("banToggle");
  if (!btn) return;
  btn.replaceChildren(document.createTextNode("Gebannt"));
  if (state.bans.size) {
    const count = document.createElement("span");
    count.className = "ban-count";
    count.textContent = `(${state.bans.size.toLocaleString("de-DE")})`;
    btn.append(count);
  }
  btn.classList.toggle("active", state.onlyBanned);
}

function paintDomains() {
  const host = document.getElementById("domains");
  if (!host) return;
  const counts = new Map();
  let bare = 0;
  const from = state.follow ? -Infinity : dataStartTs();
  for (const row of state.hits) {
    if (row.ts < from || row.ts > state.cursor) continue;
    const name = rowDomain(row);
    if (!name) {
      bare += 1;
      continue;
    }
    counts.set(name, (counts.get(name) || 0) + 1);
  }
  let names = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  if (state.domain && state.domain !== "-" && !names.some(([name]) => name === state.domain)) {
    names.unshift([state.domain, 0]);
  }
  if (names.length > 14) {
    const keep = names.slice(0, 14);
    if (state.domain && state.domain !== "-" && !keep.some(([name]) => name === state.domain)) {
      keep[keep.length - 1] = names.find(([name]) => name === state.domain);
    }
    names = keep;
  }
  const key = `${state.follow ? 1 : 0}|${state.domain}|${bare}|${names.map(([name, count]) => `${name}:${count}`).join("|")}`;
  if (key === domainKey) return;
  domainKey = key;
  host.replaceChildren();
  const add = (id, label, count, active) => {
    const btn = document.createElement("button");
    btn.type = "button";
    const name = document.createElement("span");
    name.className = "name";
    name.textContent = label;
    btn.append(name);
    if (count) {
      const num = document.createElement("span");
      num.className = "count";
      num.textContent = `(${count.toLocaleString("de-DE")})`;
      btn.append(num);
    }
    btn.title = count ? `${label} (${count.toLocaleString("de-DE")})` : label;
    btn.classList.toggle("active", active);
    btn.addEventListener("click", () => {
      state.domain = id;
      domainKey = "";
      waveKey = "";
      resetFlights();
      feed.dataset.key = "";
      savePrefs();
      paintDomains();
    });
    host.appendChild(btn);
  };
  add("", "Alle Domains", 0, !state.domain);
  for (const [name, count] of names) add(name, name, count, state.domain === name);
  if (bare) add("-", "ohne Host", bare, state.domain === "-");
}

const IP_LINE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
let ipHoverShow = 0;
let ipHoverHide = 0;
let ctxOpenedAt = 0;

function bindIpLine(node, ip) {
  if (!node || !IP_LINE.test(ip || "")) return;
  node.classList.add("ip-row");
  node.title = "Zeigen für Infos, Rechtsklick für Aktionen";
  node.addEventListener("contextmenu", (event) => {
    event.preventDefault();
    event.stopPropagation();
    hideIpHover();
    openContextMenu(event.clientX, event.clientY, rowForIp(ip));
  });
  node.addEventListener("pointerenter", () => scheduleIpHover(node, ip));
  node.addEventListener("pointerleave", () => scheduleHideIpHover());
}

function scheduleIpHover(anchor, ip) {
  clearTimeout(ipHoverHide);
  clearTimeout(ipHoverShow);
  ipHoverShow = setTimeout(() => showIpHover(anchor, ip), 240);
}

function scheduleHideIpHover() {
  clearTimeout(ipHoverShow);
  ipHoverHide = setTimeout(hideIpHover, 220);
}

function hideIpHover() {
  clearTimeout(ipHoverShow);
  clearTimeout(ipHoverHide);
  const card = document.getElementById("ipHover");
  if (card) card.hidden = true;
}

function ipFacts(ip) {
  const row = rowForIp(ip);
  let count = 0;
  let first = null;
  let last = null;
  const take = (item) => {
    if (!item || item.ip !== ip) return;
    count += 1;
    if (first == null || item.ts < first) first = item.ts;
    if (last == null || item.ts > last) last = item.ts;
  };
  for (const item of state.hits) take(item);
  if (!count) for (const item of state.events) take(item);
  return { row, count, first, last };
}

function showIpHover(anchor, ip) {
  if (!anchor || !anchor.isConnected) return;
  const menu = document.getElementById("ctx");
  if (menu && !menu.hidden) return;
  let card = document.getElementById("ipHover");
  if (!card) {
    card = document.createElement("div");
    card.id = "ipHover";
    card.className = "ip-hover";
    card.hidden = true;
    document.body.appendChild(card);
    card.addEventListener("pointerenter", () => clearTimeout(ipHoverHide));
    card.addEventListener("pointerleave", () => scheduleHideIpHover());
  }
  const { row, count, first, last } = ipFacts(ip);
  card.replaceChildren();
  const head = document.createElement("strong");
  head.className = "ip-hover-ip";
  head.textContent = ip;
  card.appendChild(head);
  const place = document.createElement("p");
  const flag = flagSrc(row.cc);
  if (flag) {
    const img = document.createElement("img");
    img.className = "tip-flag";
    img.alt = "";
    img.src = flag;
    place.appendChild(img);
  }
  place.append(document.createTextNode(row.name || row.cc || "Unbekannt"));
  card.appendChild(place);
  const orgName = row.org_name || row.org || "";
  if (orgName) {
    const org = document.createElement("p");
    const src = orgIcon(row.org || orgName);
    if (src) {
      const img = document.createElement("img");
      img.className = "org-mark";
      img.alt = "";
      img.src = src;
      img.addEventListener("error", () => img.remove());
      org.appendChild(img);
    }
    org.append(document.createTextNode(orgName));
    card.appendChild(org);
  }
  const meta = document.createElement("p");
  const bits = [];
  if (count) bits.push(`${count.toLocaleString("de-DE")} Treffer`);
  if (first) bits.push(formatTime(first));
  if (last && last !== first) bits.push(formatTime(last));
  meta.textContent = bits.join(" · ");
  if (bits.length) card.appendChild(meta);
  const actions = document.createElement("div");
  actions.className = "ip-hover-actions";
  const buttons = [
    ["details", "Details"],
    ["copy-ip", "Kopieren"],
    ["ext-abuse", "AbuseIPDB"],
    ["ext-info", "IPinfo"],
  ];
  if (state.actions) buttons.unshift(["block", "Blocken"]);
  for (const [id, label] of buttons) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = label;
    if (id === "block") btn.className = "ctx-block";
    btn.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      hideIpHover();
      runRowAction(id, row);
    });
    actions.appendChild(btn);
  }
  card.appendChild(actions);
  card.hidden = false;
  const rect = anchor.getBoundingClientRect();
  const width = card.offsetWidth || 240;
  const height = card.offsetHeight || 140;
  let left = rect.left - width - 10;
  if (left < 8) left = Math.min(rect.right + 10, window.innerWidth - width - 8);
  let top = rect.top;
  if (top + height > window.innerHeight - 8) top = Math.max(8, window.innerHeight - height - 8);
  card.style.left = `${Math.max(8, left)}px`;
  card.style.top = `${top}px`;
}

function rowForIp(ip) {
  for (let i = state.hits.length - 1; i >= 0; i -= 1) {
    if (state.hits[i].ip === ip) return state.hits[i];
  }
  for (let i = state.events.length - 1; i >= 0; i -= 1) {
    if (state.events[i].ip === ip) return state.events[i];
  }
  return { ip };
}

function openContextMenu(x, y, row) {
  const menu = document.getElementById("ctx");
  if (!menu) return;
  menu.replaceChildren();
  const items = [];
  if (row.ip && state.actions) {
    items.push(["block", "IP blocken"]);
    items.push(["unban", "Entsperren"]);
  }
  items.push(
    ["details", "Details · WHOIS laden"],
    ["copy-ip", "IP kopieren"],
    ["copy-path", "Pfad kopieren"],
    ["copy-line", "Zeile kopieren"],
    ["focus", "Land zoomen"],
    ["maps", "Google Maps öffnen"],
    ["ext-abuse", "AbuseIPDB öffnen"],
    ["ext-vt", "VirusTotal öffnen"],
    ["ext-info", "IPinfo öffnen"],
    ["ext-bgp", "BGP / WHOIS öffnen"],
  );
  for (const [id, label] of items) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = label;
    if (id === "block") btn.className = "ctx-block";
    btn.addEventListener("click", () => {
      closeContextMenu();
      runRowAction(id, row);
    });
    menu.appendChild(btn);
  }
  ctxOpenedAt = Date.now();
  menu.hidden = false;
  const pad = 8;
  const width = menu.offsetWidth || 220;
  const height = menu.offsetHeight || 280;
  menu.style.left = `${Math.min(x, window.innerWidth - width - pad)}px`;
  menu.style.top = `${Math.min(y, window.innerHeight - height - pad)}px`;
}

document.addEventListener("click", (event) => {
  if (Date.now() - ctxOpenedAt < 350) return;
  const target = event.target;
  if (target && target.closest && target.closest("#ctx, #ipHover")) return;
  closeContextMenu();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    closeContextMenu();
    hideIpHover();
    if (focusItem) closeCountry();
    return;
  }
  const tag = (event.target && event.target.tagName) || "";
  if (tag === "INPUT" || tag === "TEXTAREA" || event.target?.isContentEditable) return;
  if (event.key === "l" || event.key === "L") {
    event.preventDefault();
    document.getElementById("liveBtn")?.click();
  } else if (event.key === " " || event.code === "Space") {
    event.preventDefault();
    document.getElementById("playBtn")?.click();
  } else if (event.key === "h" || event.key === "H") {
    event.preventDefault();
    resetMapView();
  } else if (event.key === "/" && !event.ctrlKey && !event.metaKey) {
    event.preventDefault();
    document.getElementById("searchBox")?.focus();
  } else if (event.key === "e" || event.key === "E") {
    if (event.ctrlKey || event.metaKey) return;
    event.preventDefault();
    exportWindowCsv();
  } else if (event.key === "c" || event.key === "C") {
    if (state.picked?.ip) {
      event.preventDefault();
      copyText(state.picked.ip);
    }
  }
});

document.getElementById("exportBtn")?.addEventListener("click", exportWindowCsv);
paintHeaderClock();
setInterval(paintHeaderClock, 1000);

document.getElementById("inspectCollapse")?.addEventListener("click", () => {
  const inspect = document.getElementById("inspect");
  if (!inspect) return;
  setInspectCollapsed(!inspect.classList.contains("is-collapsed"));
});

document.getElementById("inspectClose")?.addEventListener("click", () => {
  closeCountry();
});

document.getElementById("domainFoldBtn")?.addEventListener("click", () => {
  const fold = document.getElementById("domainFold");
  if (!fold) return;
  setDomainFold(!fold.classList.contains("is-collapsed"));
  savePrefs();
});

document.getElementById("controlsFold")?.addEventListener("click", () => {
  setControlsFold(!document.body.classList.contains("controls-collapsed"));
  savePrefs();
});

function setMobilePanel(panel) {
  const next = panel === "log" ? "log" : "map";
  document.body.classList.toggle("panel-map", next === "map");
  document.body.classList.toggle("panel-log", next === "log");
  const tabs = document.getElementById("mobileTabs");
  if (tabs) {
    for (const btn of tabs.querySelectorAll("button[data-panel]")) {
      btn.classList.toggle("active", btn.dataset.panel === next);
    }
  }
  try { localStorage.setItem("livemap.panel", next); } catch (err) { /* ignore */ }
  requestAnimationFrame(() => {
    resize();
    waveKey = "";
    waveMarkKey = "";
  });
}

document.getElementById("mobileTabs")?.addEventListener("click", (event) => {
  const btn = event.target.closest("button[data-panel]");
  if (!btn) return;
  setMobilePanel(btn.dataset.panel);
});

try {
  const savedPanel = localStorage.getItem("livemap.panel");
  if (savedPanel === "log" || savedPanel === "map") setMobilePanel(savedPanel);
} catch (err) { /* ignore */ }

function authRedirect(res) {
  if (res && (res.status === 401 || res.status === 302)) {
    location.href = "/login";
    return true;
  }
  return false;
}

async function api(url, opts) {
  const res = await fetch(url, { credentials: "same-origin", ...(opts || {}) });
  if (authRedirect(res)) throw new Error("auth");
  return res;
}

function setAccountName(name) {
  const label = name || "Konto";
  const nameEl = document.getElementById("accountName");
  const btn = document.getElementById("accountBtn");
  const settingsUser = document.getElementById("settingsUser");
  if (nameEl) nameEl.textContent = label;
  if (btn) btn.title = label;
  if (settingsUser) settingsUser.textContent = label;
}

function closeAccountMenu() {
  const menu = document.getElementById("accountMenu");
  const btn = document.getElementById("accountBtn");
  if (menu) menu.hidden = true;
  if (btn) btn.setAttribute("aria-expanded", "false");
}

document.getElementById("accountBtn")?.addEventListener("click", (event) => {
  event.stopPropagation();
  const menu = document.getElementById("accountMenu");
  const btn = document.getElementById("accountBtn");
  if (!menu || !btn) return;
  const willOpen = menu.hidden;
  menu.hidden = !willOpen;
  btn.setAttribute("aria-expanded", willOpen ? "true" : "false");
});

document.addEventListener("click", (event) => {
  if (!event.target.closest("#account")) closeAccountMenu();
});

document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  closeAccountMenu();
  hideSettings();
});

function formatDuration(sec) {
  if (!Number.isFinite(sec) || sec < 0) return "–";
  const total = Math.round(sec);
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const mins = Math.floor((total % 3600) / 60);
  if (days) return `${days} T ${hours} Std`;
  if (hours) return `${hours} Std ${mins} Min`;
  if (mins) return `${mins} Min`;
  return `${total} Sek`;
}

function isAdminUser() {
  return !!(state.user && state.user.role === "admin");
}

function syncAdminTab() {
  const adminTab = document.querySelector('.settings-nav button[data-tab="administration"]');
  if (adminTab) adminTab.hidden = !isAdminUser();
  if (!isAdminUser()) {
    const panel = document.querySelector('.settings-panel[data-panel="administration"]');
    if (panel) panel.hidden = true;
    const active = document.querySelector(".settings-nav button.active");
    if (active && active.dataset.tab === "administration") setSettingsTab("account");
  }
}

function setSettingsTab(id) {
  if (id === "administration" && !isAdminUser()) id = "account";
  document.querySelectorAll(".settings-nav button").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === id);
  });
  document.querySelectorAll(".settings-panel").forEach((panel) => {
    panel.hidden = panel.dataset.panel !== id;
  });
  if (id === "administration") loadAdmin();
}

function roleLabel(role) {
  return role === "admin" ? "Administration" : "Zuschauen";
}

async function loadAdmin() {
  const users = document.getElementById("userList");
  const invites = document.getElementById("inviteList");
  if (!users || !invites) return;
  const res = await fetch("/api/users", { credentials: "same-origin" });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    users.innerHTML = "";
    invites.innerHTML = "";
    return;
  }
  users.replaceChildren();
  for (const user of data.users || []) {
    const li = document.createElement("li");
    const name = document.createElement("span");
    name.textContent = user.username;
    const role = document.createElement("span");
    role.className = "role";
    role.textContent = roleLabel(user.role);
    li.append(name, role);
    users.appendChild(li);
  }
  invites.replaceChildren();
  for (const item of data.invites || []) {
    const li = document.createElement("li");
    const name = document.createElement("span");
    name.textContent = item.username;
    const drop = document.createElement("button");
    drop.type = "button";
    drop.textContent = "Zurückziehen";
    drop.addEventListener("click", async () => {
      await fetch("/api/users/revoke", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: item.username }),
      });
      loadAdmin();
    });
    li.append(name, drop);
    invites.appendChild(li);
  }
  if (!invites.children.length) {
    const li = document.createElement("li");
    li.textContent = "Keine offenen Einladungen";
    invites.appendChild(li);
  }
}

document.getElementById("setupReset")?.addEventListener("click", () => {
  const confirmBox = document.getElementById("setupResetConfirm");
  const msg = document.getElementById("setupResetMsg");
  if (msg) msg.textContent = "";
  if (confirmBox) confirmBox.hidden = false;
});

document.getElementById("setupResetNo")?.addEventListener("click", () => {
  const confirmBox = document.getElementById("setupResetConfirm");
  if (confirmBox) confirmBox.hidden = true;
});

document.getElementById("setupResetYes")?.addEventListener("click", async () => {
  const yes = document.getElementById("setupResetYes");
  const msg = document.getElementById("setupResetMsg");
  const box = document.getElementById("setupResetCode");
  if (msg) {
    msg.textContent = "";
    msg.className = "settings-msg";
  }
  if (yes) yes.disabled = true;
  try {
    const res = await fetch("/api/setup/reset", {
      method: "POST",
      credentials: "same-origin",
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.ok || !data.code) {
      if (msg) {
        msg.textContent = data.error || "Zurücksetzen fehlgeschlagen";
        msg.className = "settings-msg is-bad";
      }
      if (yes) yes.disabled = false;
      return;
    }
    const reset = document.getElementById("setupReset");
    const confirmBox = document.getElementById("setupResetConfirm");
    if (reset) reset.hidden = true;
    if (confirmBox) confirmBox.hidden = true;
    if (box) {
      box.hidden = false;
      box.replaceChildren();
      const lead = document.createElement("span");
      lead.textContent = "Alle Konten sind gelöscht. Dieser Einrichtungscode gilt nur jetzt hier. Danach liegt er auf dem Server.";
      const code = document.createElement("code");
      code.textContent = data.code;
      const copy = document.createElement("button");
      copy.type = "button";
      copy.textContent = "Code kopieren";
      copy.addEventListener("click", () => copyText(data.code));
      const open = document.createElement("a");
      open.className = "setup-go";
      open.href = "/setup";
      open.textContent = "Einrichtung öffnen";
      box.append(lead, code, copy, open);
    }
  } catch (err) {
    if (msg) {
      msg.textContent = "Netzwerkfehler";
      msg.className = "settings-msg is-bad";
    }
    if (yes) yes.disabled = false;
  }
});

document.getElementById("inviteForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const msg = document.getElementById("inviteMsg");
  const box = document.getElementById("inviteLink");
  const save = document.getElementById("inviteSave");
  const username = document.getElementById("inviteUser")?.value.trim() || "";
  if (msg) {
    msg.textContent = "";
    msg.className = "settings-msg";
  }
  if (save) save.disabled = true;
  try {
    const res = await fetch("/api/users", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.ok) {
      if (msg) {
        msg.textContent = data.error || "Einladung fehlgeschlagen";
        msg.className = "settings-msg is-bad";
      }
      return;
    }
    if (box) {
      box.hidden = false;
      box.replaceChildren();
      const lead = document.createElement("span");
      lead.textContent = "Link nur jetzt sichtbar. Danach liegt nur noch der Schlüssel auf dem Server.";
      const code = document.createElement("code");
      code.textContent = data.url;
      const copy = document.createElement("button");
      copy.type = "button";
      copy.textContent = "Link kopieren";
      copy.addEventListener("click", () => copyText(data.url));
      box.append(lead, code, copy);
    }
    if (msg) {
      msg.textContent = "Einladung erstellt";
      msg.className = "settings-msg is-ok";
    }
    const field = document.getElementById("inviteUser");
    if (field) field.value = "";
    loadAdmin();
  } finally {
    if (save) save.disabled = false;
  }
});

function openSheet(panel) {
  if (!panel) return;
  if (window.matchMedia("(max-width: 720px)").matches && document.body.classList.contains("panel-log")) {
    setMobilePanel("map");
  }
  panel.dataset.closing = "";
  panel.hidden = false;
  panel.classList.remove("is-open");
  void panel.offsetWidth;
  panel.classList.add("is-open");
}

function closeSheet(panel) {
  if (!panel || panel.hidden || panel.dataset.closing === "1") return;
  panel.dataset.closing = "1";
  panel.classList.remove("is-open");
  const finish = () => {
    if (panel.dataset.closing !== "1") return;
    panel.dataset.closing = "";
    panel.hidden = true;
  };
  const onEnd = (event) => {
    if (event.target !== panel || event.propertyName !== "transform") return;
    panel.removeEventListener("transitionend", onEnd);
    finish();
  };
  panel.addEventListener("transitionend", onEnd);
  setTimeout(finish, 340);
}

let analyticsKey = "";
let analyticsDrawn = 0;
let analyticsSpan = 12 * 3600;
let analyticsCc = "";
let analyticsKind = "";
let analyticsFilterKey = "";
const analyticsCharts = new WeakMap();
const ANALYTICS_SPANS = [
  [3600, "1 Std"],
  [12 * 3600, "12 Std"],
  [24 * 3600, "24 Std"],
  [7 * 86400, "7 Tage"],
  [0, "Alles"],
];

function analyticsOrigin() {
  let first = Date.now() / 1000;
  for (const row of state.hits) if (row.ts && row.ts < first) first = row.ts;
  for (const row of state.events) if (row.ts && row.ts < first) first = row.ts;
  return first;
}

function analyticsKindOf(row) {
  if (!row) return "page";
  if (analyticsKind === "self") return viewKind(row);
  return row.kind || "page";
}

function analyticsMatch(row, start, end) {
  if (!row || row.ts < start || row.ts > end) return false;
  if (analyticsCc && row.cc !== analyticsCc) return false;
  if (analyticsKind && analyticsKindOf(row) !== analyticsKind) return false;
  return true;
}

function countBins(rows, start, end, n, field) {
  const bins = field ? Array.from({ length: n }, () => new Set()) : new Array(n).fill(0);
  const span = Math.max(1, end - start);
  for (const row of rows) {
    if (row.ts < start || row.ts >= end) continue;
    const index = Math.min(n - 1, Math.floor(((row.ts - start) / span) * n));
    if (field) {
      const value = row[field];
      if (value) bins[index].add(value);
    } else bins[index] += 1;
  }
  return field ? bins.map((set) => set.size) : bins;
}

function paintChart(canvas, values) {
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  const dpr = Math.min(2, devicePixelRatio || 1);
  const width = Math.max(1, Math.floor(rect.width * dpr));
  const height = Math.max(1, Math.floor(rect.height * dpr));
  if (canvas.width !== width || canvas.height !== height) {
    canvas.width = width;
    canvas.height = height;
  }
  const g = canvas.getContext("2d");
  g.clearRect(0, 0, width, height);
  const light = document.documentElement.dataset.theme === "light";
  const stroke = light ? "#4d6274" : "#9aabba";
  const fill = light ? "rgba(77, 98, 116, 0.16)" : "rgba(154, 171, 186, 0.28)";
  const max = Math.max(1, ...values);
  const step = values.length > 1 ? width / (values.length - 1) : width;
  const pad = Math.max(2, dpr * 2);
  g.beginPath();
  values.forEach((value, i) => {
    const x = values.length > 1 ? i * step : width / 2;
    const y = height - pad - (value / max) * (height - pad * 2);
    if (i === 0) g.moveTo(x, y);
    else g.lineTo(x, y);
  });
  g.strokeStyle = stroke;
  g.lineWidth = Math.max(1, dpr);
  g.stroke();
  g.lineTo(width, height);
  g.lineTo(0, height);
  g.closePath();
  g.fillStyle = fill;
  g.fill();
}

function drawAreaChart(canvas, values) {
  if (!canvas) return;
  const prev = analyticsCharts.get(canvas);
  const from = prev && prev.values.length === values.length ? prev.values : null;
  const token = (prev?.token || 0) + 1;
  analyticsCharts.set(canvas, { values: values.slice(), token });
  const same = from && from.every((value, i) => value === values[i]);
  if (!from || same) {
    paintChart(canvas, values);
    return;
  }
  const start = performance.now();
  const frame = (now) => {
    const current = analyticsCharts.get(canvas);
    if (!current || current.token !== token) return;
    const t = Math.min(1, (now - start) / 460);
    const ease = t * t * (3 - 2 * t);
    paintChart(canvas, values.map((value, i) => from[i] + (value - from[i]) * ease));
    if (t < 1) requestAnimationFrame(frame);
  };
  requestAnimationFrame(frame);
}

function analyticsChip(label, active, onClick) {
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = active ? "active" : "";
  btn.textContent = label;
  btn.addEventListener("click", onClick);
  return btn;
}

function paintAnalyticsControls(start, end) {
  const countries = new Map();
  for (const row of state.hits) {
    if (!row || row.ts < start || row.ts > end || !row.cc) continue;
    if (analyticsKind && analyticsKindOf(row) !== analyticsKind) continue;
    countries.set(row.cc, (countries.get(row.cc) || 0) + 1);
  }
  const tops = [...countries.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
  if (analyticsCc && !countries.has(analyticsCc)) analyticsCc = "";
  const key = [
    analyticsSpan,
    analyticsCc,
    analyticsKind,
    tops.map(([cc, n]) => `${cc}:${n}`).join(","),
  ].join("|");
  if (key === analyticsFilterKey) return;
  analyticsFilterKey = key;
  const spans = document.getElementById("anSpans");
  const countryHost = document.getElementById("anCountriesPick");
  const services = document.getElementById("anServices");
  if (!spans || !countryHost || !services) return;
  const choose = (apply) => () => {
    apply();
    analyticsFilterKey = "";
    analyticsDrawn = 0;
    paintAnalytics();
  };
  spans.replaceChildren();
  for (const [value, label] of ANALYTICS_SPANS) {
    spans.append(analyticsChip(label, analyticsSpan === value, choose(() => { analyticsSpan = value; })));
  }
  countryHost.replaceChildren();
  countryHost.append(analyticsChip("Alle Länder", !analyticsCc, choose(() => { analyticsCc = ""; })));
  for (const [cc] of tops) {
    const btn = analyticsChip(cc, analyticsCc === cc, choose(() => { analyticsCc = cc; }));
    const src = flagSrc(cc);
    if (src) {
      const img = document.createElement("img");
      img.src = src;
      img.alt = "";
      btn.prepend(img);
    }
    countryHost.append(btn);
  }
  services.replaceChildren();
  services.append(analyticsChip("Alle Dienste", !analyticsKind, choose(() => { analyticsKind = ""; })));
  for (const [id, label] of KINDS) {
    services.append(analyticsChip(label, analyticsKind === id, choose(() => { analyticsKind = id; })));
  }
}

function paintAnalytics() {
  const panel = document.getElementById("analytics");
  if (!panel || panel.hidden) return;
  const now = Date.now() / 1000;
  const start = analyticsSpan > 0 ? now - analyticsSpan : analyticsOrigin();
  paintAnalyticsControls(start, now);
  const probe = document.getElementById("anHitsChart");
  if (!probe || probe.getBoundingClientRect().width < 2) return;
  const nowMs = performance.now();
  if (analyticsDrawn && nowMs - analyticsDrawn < 900) return;
  analyticsDrawn = nowMs;
  const hits = state.hits.filter((row) => analyticsMatch(row, start, now));
  const bans = state.events.filter((row) => BAN_KINDS.has(row.kind) && analyticsMatch(row, start, now));
  const ips = new Set();
  const countries = new Set();
  const banIps = new Set();
  const kinds = new Map();
  for (const row of hits) {
    if (row.ip) ips.add(row.ip);
    if (row.cc) countries.add(row.cc);
    const kind = row.kind || "page";
    kinds.set(kind, (kinds.get(kind) || 0) + 1);
  }
  for (const row of bans) if (row.ip) banIps.add(row.ip);
  const numbers = [
    ["anHits", hits.length],
    ["anBanned", banIps.size],
    ["anIps", ips.size],
    ["anCountries", countries.size],
  ];
  for (const [id, value] of numbers) {
    const node = document.getElementById(id);
    if (node) node.textContent = value.toLocaleString("de-DE");
  }
  drawAreaChart(document.getElementById("anHitsChart"), countBins(hits, start, now, 28));
  drawAreaChart(document.getElementById("anBannedChart"), countBins(bans, start, now, 28));
  drawAreaChart(document.getElementById("anIpsChart"), countBins(hits, start, now, 28, "ip"));
  drawAreaChart(document.getElementById("anCountriesChart"), countBins(hits, start, now, 28, "cc"));
  const tableKey = `${hits.length}|${banIps.size}|${ips.size}|${countries.size}|${analyticsSpan}|${analyticsCc}|${analyticsKind}`;
  if (tableKey === analyticsKey) return;
  analyticsKey = tableKey;
  const table = document.getElementById("anKinds");
  if (!table) return;
  table.replaceChildren();
  const rows = [...kinds.entries()].sort((a, b) => b[1] - a[1]);
  for (const [kind, count] of rows) {
    const tr = document.createElement("tr");
    const name = document.createElement("td");
    name.textContent = (KIND[kind] || KIND.page).label;
    const value = document.createElement("td");
    value.textContent = count.toLocaleString("de-DE");
    tr.append(name, value);
    table.append(tr);
  }
}

function showAnalytics() {
  closeSheet(document.getElementById("settings"));
  const panel = document.getElementById("analytics");
  openSheet(panel);
  analyticsDrawn = 0;
  analyticsKey = "";
  paintAnalytics();
}

function hideAnalytics() {
  closeSheet(document.getElementById("analytics"));
}

function showSettings() {
  closeSheet(document.getElementById("analytics"));
  const panel = document.getElementById("settings");
  if (!panel) return;
  openSheet(panel);
  setSettingsTab("account");
  loadSettingsStatus();
}

function hideSettings() {
  closeSheet(document.getElementById("settings"));
}

function statGrid(items) {
  const grid = document.createElement("div");
  grid.className = "settings-stats";
  for (const [value, label] of items) {
    const cell = document.createElement("div");
    const strong = document.createElement("strong");
    strong.textContent = value;
    const span = document.createElement("span");
    span.textContent = label;
    cell.append(strong, span);
    grid.append(cell);
  }
  return grid;
}

function paintSettingsStatus(data) {
  const fail = document.getElementById("settingsFail2ban");
  const services = document.getElementById("settingsServices");
  const general = document.getElementById("settingsGeneral");
  if (fail) {
    fail.replaceChildren();
    const head = document.createElement("p");
    head.className = "settings-note";
    head.textContent = data.fail2ban.up
      ? `Fail2ban antwortet · ${data.fail2ban.banned} Adressen gesperrt`
      : "Fail2ban antwortet nicht";
    fail.append(head, statGrid([
      [String(data.fail2ban.banned), "gesperrt"],
      [String(data.fail2ban.jails.length), "Jails"],
    ]));
    const table = document.createElement("table");
    table.className = "settings-table";
    const caption = document.createElement("tr");
    caption.innerHTML = "<th>Jail</th><th>Gesperrt</th>";
    table.append(caption);
    for (const jail of data.fail2ban.jails) {
      const tr = document.createElement("tr");
      const name = document.createElement("td");
      name.textContent = jail.jail;
      const count = document.createElement("td");
      count.textContent = String(jail.banned);
      tr.append(name, count);
      table.append(tr);
    }
    fail.append(table);
  }
  if (services) {
    services.replaceChildren();
    for (const svc of data.services) {
      const row = document.createElement("div");
      row.className = "svc";
      const dot = document.createElement("span");
      dot.className = `svc-dot ${svc.up ? "is-up" : "is-down"}`;
      const title = document.createElement("strong");
      title.textContent = svc.name;
      const text = document.createElement("p");
      const state = svc.up ? "läuft" : "keine Antwort";
      const uptime = svc.uptime != null ? ` · seit ${formatDuration(svc.uptime)}` : "";
      text.textContent = `${state}${uptime}${svc.detail ? ` · ${svc.detail}` : ""}`;
      row.append(dot, title, text);
      services.append(row);
    }
  }
  if (general) {
    const g = data.general;
    general.replaceChildren();
    const list = document.createElement("dl");
    const fields = [
      ["Name", g.name || ""],
      ["Host", g.hostname || ""],
      ["Anbieter", g.hoster || ""],
      ["Sitzung", g.session_days ? `${g.session_days} Tage` : ""],
      ["Karte", "Live, Filter bleiben in diesem Browser"],
    ];
    for (const [label, value] of fields) {
      if (!value) continue;
      const dt = document.createElement("dt");
      dt.textContent = label;
      const dd = document.createElement("dd");
      dd.textContent = value;
      list.append(dt, dd);
    }
    general.append(list);
  }
}

async function loadSettingsStatus() {
  const boxes = ["settingsFail2ban", "settingsServices", "settingsGeneral"];
  for (const id of boxes) {
    const node = document.getElementById(id);
    if (node && !node.childElementCount) node.textContent = "Wird gelesen …";
  }
  try {
    const res = await api("/api/status");
    const data = await res.json();
    if (!res.ok || !data.ok) throw new Error("status");
    paintSettingsStatus(data);
  } catch (err) {
    if (String(err && err.message) === "auth") return;
    for (const id of boxes) {
      const node = document.getElementById(id);
      if (node) node.textContent = "Status nicht erreichbar";
    }
  }
}

document.getElementById("settingsBtn")?.addEventListener("click", () => {
  closeAccountMenu();
  const msg = document.getElementById("settingsMsg");
  if (msg) {
    msg.textContent = "";
    msg.className = "settings-msg";
  }
  showSettings();
});

document.getElementById("analyticsBtn")?.addEventListener("click", () => {
  closeAccountMenu();
  showAnalytics();
});

document.getElementById("analyticsClose")?.addEventListener("click", () => {
  hideAnalytics();
});

document.querySelectorAll(".settings-nav button").forEach((btn) => {
  btn.addEventListener("click", () => setSettingsTab(btn.dataset.tab));
});

document.getElementById("settingsClose")?.addEventListener("click", () => {
  hideSettings();
});

document.getElementById("settingsForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const msg = document.getElementById("settingsMsg");
  const save = document.getElementById("settingsSave");
  const current = document.getElementById("pwCurrent")?.value || "";
  const next = document.getElementById("pwNew")?.value || "";
  const again = document.getElementById("pwAgain")?.value || "";
  const show = (text, kind) => {
    if (!msg) return;
    msg.textContent = text;
    msg.className = `settings-msg${kind ? ` is-${kind}` : ""}`;
  };
  if (next.length < 8) {
    show("Mindestens 8 Zeichen", "bad");
    return;
  }
  if (next !== again) {
    show("Passwörter stimmen nicht überein", "bad");
    return;
  }
  if (save) save.disabled = true;
  try {
    const res = await api("/api/password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ current, password: next }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.ok) {
      show(data.error || "Speichern fehlgeschlagen", "bad");
      return;
    }
    document.getElementById("settingsForm")?.reset();
    show("Passwort gespeichert", "ok");
  } catch (err) {
    if (String(err && err.message) !== "auth") show("Netzwerkfehler", "bad");
  } finally {
    if (save) save.disabled = false;
  }
});

document.getElementById("logoutBtn")?.addEventListener("click", async () => {
  try {
    await fetch("/api/logout", { method: "POST", credentials: "same-origin" });
  } catch (err) { /* ignore */ }
  location.href = "/login";
});

Promise.all([
  api("/world.geojson").then((res) => res.json()),
  api("/api/bootstrap").then((res) => res.json()),
]).then(([world, data]) => {
  state.features = (world.features || []).map(prepareCountry);
  state.server = data.server;
  state.events = data.events || [];
  state.hits = data.hits || [];
  state.user = data.user || null;
  state.selfIp = (data.user && data.user.ip) || "";
  setAccountName(data.user && data.user.username);
  syncAdminTab();
  setBans(data.bans);
  paintBanButton();
  state.actions = !!data.actions;
  if (Array.isArray(data.jails) && data.jails.length) state.jails = data.jails;
  state.cursor = Math.max(latestTs(), Date.now() / 1000);
  const loading = document.getElementById("loading");
  if (loading) loading.hidden = true;
  const boot = document.getElementById("boot");
  if (boot) boot.hidden = true;
  document.body.classList.remove("is-loading");
  document.body.classList.add("is-ready");
  setLinkStatus("boot");
  connectStream();
  setInterval(() => {
    api("/api/bans").then((res) => res.json()).then((payload) => {
      if (payload && payload.bans) {
        setBans(payload.bans);
        paintBanButton();
        feed.dataset.key = "";
      }
    }).catch(() => {});
  }, 45000);
}).catch((err) => {
  if (String(err && err.message) === "auth") return;
  setLinkStatus("down");
  document.body.classList.remove("is-loading");
  const boot = document.getElementById("boot");
  if (boot) boot.hidden = true;
  const loading = document.getElementById("loading");
  if (loading) {
    loading.hidden = false;
    loading.textContent = "Die Karte konnte nicht geladen werden.";
  }
});

armDesktopNotes();
requestAnimationFrame(render);
