const canvas = document.getElementById("loginMap");
const ctx = canvas.getContext("2d");
const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const target = { lon: 13.405, lat: 52.52 };
const origins = [
  ["Shanghai", 121.47, 31.23],
  ["Singapur", 103.85, 1.29],
  ["Tokio", 139.69, 35.69],
  ["Mumbai", 72.88, 19.08],
  ["Sydney", 151.21, -33.87],
  ["São Paulo", -46.63, -23.55],
  ["New York", -74.01, 40.71],
  ["Lagos", 3.38, 6.52],
  ["Moskau", 37.62, 55.76],
  ["London", -0.13, 51.51],
  ["Johannesburg", 28.05, -26.2],
  ["Seoul", 126.98, 37.57],
  ["Istanbul", 28.98, 41.01],
  ["Los Angeles", -118.24, 34.05],
  ["Jakarta", 106.85, -6.21],
  ["Kairo", 31.24, 30.04],
  ["Toronto", -79.38, 43.65],
  ["Bangkok", 100.5, 13.76],
  ["Mexiko-Stadt", -99.13, 19.43],
  ["Dubai", 55.27, 25.2],
  ["Paris", 2.35, 48.86],
  ["Buenos Aires", -58.38, -34.6],
];
const colors = ["#c24b3c", "#c9a24a", "#6d8ea3", "#a86b52", "#8b949e"];
let features = [];
let mapLayer = null;
let mapKey = "";
let viewW = 0;
let viewH = 0;
const flights = [];
const impacts = [];
let originIndex = 0;
let spawnAt = 0;

function placeText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value || "—";
}

function formatPlace(lat, lon) {
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return "—";
  const ns = lat >= 0 ? "N" : "S";
  const ew = lon >= 0 ? "E" : "W";
  return `${Math.abs(lat).toFixed(2)}° ${ns}, ${Math.abs(lon).toFixed(2)}° ${ew}`;
}

const NAME_CC = {
  Afghanistan: "AF", Angola: "AO", Albania: "AL", "United Arab Emirates": "AE", Argentina: "AR",
  Armenia: "AM", Australia: "AU", Austria: "AT", Azerbaijan: "AZ", Burundi: "BI", Belgium: "BE",
  Benin: "BJ", "Burkina Faso": "BF", Bangladesh: "BD", Bulgaria: "BG", "The Bahamas": "BS",
  "Bosnia and Herzegovina": "BA", Belarus: "BY", Belize: "BZ", Bolivia: "BO", Brazil: "BR",
  Brunei: "BN", Bhutan: "BT", Botswana: "BW", "Central African Republic": "CF", Canada: "CA",
  Switzerland: "CH", Chile: "CL", China: "CN", "Ivory Coast": "CI", Cameroon: "CM",
  "Democratic Republic of the Congo": "CD", "Republic of the Congo": "CG", Colombia: "CO",
  "Costa Rica": "CR", Cuba: "CU", Cyprus: "CY", "Czech Republic": "CZ", Germany: "DE",
  Djibouti: "DJ", Denmark: "DK", "Dominican Republic": "DO", Algeria: "DZ", Ecuador: "EC",
  Egypt: "EG", Eritrea: "ER", Spain: "ES", Estonia: "EE", Ethiopia: "ET", Finland: "FI",
  France: "FR", Gabon: "GA", England: "GB", Georgia: "GE", Ghana: "GH", Greece: "GR",
  Greenland: "GL", Guatemala: "GT", Honduras: "HN", Croatia: "HR", Haiti: "HT", Hungary: "HU",
  Indonesia: "ID", India: "IN", Ireland: "IE", Iran: "IR", Iraq: "IQ", Iceland: "IS",
  Israel: "IL", Italy: "IT", Jamaica: "JM", Jordan: "JO", Japan: "JP", Kazakhstan: "KZ",
  Kenya: "KE", Kyrgyzstan: "KG", Cambodia: "KH", "South Korea": "KR", Kosovo: "XK",
  Kuwait: "KW", Laos: "LA", Lebanon: "LB", Liberia: "LR", Libya: "LY", "Sri Lanka": "LK",
  Lesotho: "LS", Lithuania: "LT", Luxembourg: "LU", Latvia: "LV", Morocco: "MA", Moldova: "MD",
  Madagascar: "MG", Mexico: "MX", Macedonia: "MK", Mali: "ML", Myanmar: "MM", Montenegro: "ME",
  Mongolia: "MN", Mozambique: "MZ", Mauritania: "MR", Malawi: "MW", Malaysia: "MY",
  Namibia: "NA", Niger: "NE", Nigeria: "NG", Nicaragua: "NI", Netherlands: "NL", Norway: "NO",
  Nepal: "NP", "New Zealand": "NZ", Oman: "OM", Pakistan: "PK", Panama: "PA", Peru: "PE",
  Philippines: "PH", "Papua New Guinea": "PG", Poland: "PL", "Puerto Rico": "PR",
  "North Korea": "KP", Portugal: "PT", Paraguay: "PY", Qatar: "QA", Romania: "RO", Russia: "RU",
  Rwanda: "RW", "Saudi Arabia": "SA", Sudan: "SD", Senegal: "SN", "El Salvador": "SV",
  Somalia: "SO", "Republic of Serbia": "RS", Suriname: "SR", Slovakia: "SK", Slovenia: "SI",
  Sweden: "SE", Swaziland: "SZ", Syria: "SY", Chad: "TD", Togo: "TG", Thailand: "TH",
  Tajikistan: "TJ", Turkmenistan: "TM", "East Timor": "TL", "Trinidad and Tobago": "TT",
  Tunisia: "TN", Turkey: "TR", Taiwan: "TW", "United Republic of Tanzania": "TZ", Uganda: "UG",
  Ukraine: "UA", Uruguay: "UY", USA: "US", Uzbekistan: "UZ", Venezuela: "VE", Vietnam: "VN",
  "West Bank": "PS", Yemen: "YE", "South Africa": "ZA", Zambia: "ZM", Zimbabwe: "ZW",
};
let hostFeature = null;
let hostFlag = null;

function ringHolds(ring, lon, lat) {
  let minLon = 180;
  let maxLon = -180;
  for (const pair of ring) {
    minLon = Math.min(minLon, pair[0]);
    maxLon = Math.max(maxLon, pair[0]);
  }
  if (maxLon - minLon > 180) return false;
  let inside = false;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i, i += 1) {
    const yi = ring[i][1];
    const yj = ring[j][1];
    if ((yi > lat) === (yj > lat)) continue;
    const xi = ring[i][0];
    const xj = ring[j][0];
    const x = ((xj - xi) * (lat - yi)) / (yj - yi) + xi;
    if (lon < x) inside = !inside;
  }
  return inside;
}

function geometryHolds(geometry, lon, lat) {
  const polys = geometry.type === "Polygon" ? [geometry.coordinates] : geometry.coordinates;
  for (const poly of polys) {
    if (!poly[0] || !ringHolds(poly[0], lon, lat)) continue;
    let hole = false;
    for (let h = 1; h < poly.length; h += 1) {
      if (ringHolds(poly[h], lon, lat)) hole = true;
    }
    if (!hole) return true;
  }
  return false;
}

function locateHost() {
  hostFeature = null;
  if (!features.length || !Number.isFinite(target.lat) || !Number.isFinite(target.lon)) return;
  for (const feature of features) {
    if (!feature.geometry) continue;
    if (geometryHolds(feature.geometry, target.lon, target.lat)) {
      hostFeature = feature;
      break;
    }
  }
  const name = hostFeature && hostFeature.properties && hostFeature.properties.name;
  const cc = NAME_CC[name] || "";
  if (!cc) return;
  if (hostFlag && hostFlag.dataset.cc === cc) return;
  hostFlag = new Image();
  hostFlag.dataset.cc = cc;
  hostFlag.onload = () => { if (reduced) requestAnimationFrame(frame); };
  hostFlag.src = `/flags/${cc.toLowerCase()}.svg`;
}

function drawHostCountry(box) {
  if (!hostFeature) return;
  const img = hostFlag;
  const ready = img && img.complete && (img.naturalWidth > 0 || img.dataset.cc);
  if (ready) {
    const nw = img.naturalWidth || 640;
    const nh = img.naturalHeight || 480;
    const polys = hostFeature.geometry.type === "Polygon" ? [hostFeature.geometry.coordinates] : hostFeature.geometry.coordinates;
    let minX = Infinity;
    let maxX = -Infinity;
    let minY = Infinity;
    let maxY = -Infinity;
    for (const poly of polys) {
      const ring = poly[0];
      if (!ring) continue;
      for (const pair of ring) {
        const point = project(pair[0], pair[1], box);
        minX = Math.min(minX, point[0]);
        maxX = Math.max(maxX, point[0]);
        minY = Math.min(minY, point[1]);
        maxY = Math.max(maxY, point[1]);
      }
    }
    const areaW = maxX - minX;
    const areaH = maxY - minY;
    if (areaW > 8 && areaH > 8) {
      const ratio = nw / nh;
      let dw = areaW;
      let dh = areaW / ratio;
      if (dh < areaH) {
        dh = areaH;
        dw = areaH * ratio;
      }
      ctx.save();
      ctx.beginPath();
      traceGeometry(hostFeature.geometry, box, ctx);
      ctx.clip();
      ctx.globalAlpha = 1;
      ctx.drawImage(img, minX + (areaW - dw) / 2, minY + (areaH - dh) / 2, dw, dh);
      ctx.restore();
    }
  }
  const light = document.documentElement.dataset.theme === "light";
  ctx.beginPath();
  traceGeometry(hostFeature.geometry, box, ctx);
  ctx.globalAlpha = 0.95;
  ctx.lineWidth = 2.2;
  ctx.strokeStyle = light ? "rgba(28, 40, 52, 0.95)" : "rgba(244, 247, 250, 0.95)";
  ctx.stroke();
  ctx.globalAlpha = 1;
}

fetch("/api/host", { credentials: "same-origin" })
  .then((res) => res.ok ? res.json() : null)
  .then((data) => {
    if (!data) return;
    placeText("hostName", data.name || data.hostname);
    placeText("hostHostname", data.hostname);
    placeText("hostHoster", data.hoster);
    if (Number.isFinite(data.lat) && Number.isFinite(data.lon)) {
      target.lat = data.lat;
      target.lon = data.lon;
      mapKey = "";
    }
    placeText("hostPlace", formatPlace(target.lat, target.lon));
    const hostLine = document.getElementById("hostHostname");
    if (hostLine) hostLine.hidden = !data.hostname || data.hostname === (data.name || data.hostname);
    const hostBox = document.getElementById("loginHost");
    if (hostBox) hostBox.hidden = false;
    locateHost();
    if (reduced) requestAnimationFrame(frame);
  })
  .catch(() => {});

function project(lon, lat, box) {
  return [
    box.x + ((lon + 180) / 360) * box.w,
    box.y + ((90 - lat) / 180) * box.h,
  ];
}

function viewBox() {
  const w = canvas.width;
  const h = canvas.height;
  let bw = w;
  let bh = bw / 2;
  if (bh < h) {
    bh = h;
    bw = bh * 2;
  }
  return { x: (w - bw) / 2, y: (h - bh) / 2, w: bw, h: bh };
}

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
  mapKey = "";
}

function traceGeometry(geometry, box, context) {
  const polys = geometry.type === "Polygon" ? [geometry.coordinates] : geometry.coordinates;
  for (const poly of polys) {
    for (const ring of poly) {
      let open = false;
      let prev = null;
      for (const pair of ring) {
        const lon = pair[0];
        const lat = pair[1];
        if (prev && Math.abs(lon - prev[0]) > 180) {
          if (open) context.closePath();
          open = false;
        }
        const point = project(lon, lat, box);
        if (!open) {
          context.moveTo(point[0], point[1]);
          open = true;
        } else context.lineTo(point[0], point[1]);
        prev = pair;
      }
      if (open) context.closePath();
    }
  }
}

function demoPaint() {
  const light = document.documentElement.dataset.theme === "light";
  return light
    ? { sea: "#e7edf2", land: "#c5d0da", grid: "rgba(90, 104, 118, 0.28)", stroke: "rgba(70, 84, 98, 0.4)" }
    : { sea: "#0b0e11", land: "#3a4450", grid: "rgba(122, 137, 152, 0.2)", stroke: "rgba(152, 167, 182, 0.34)" };
}

function ensureMap(box) {
  const paint = demoPaint();
  const key = `${canvas.width}x${canvas.height}|${box.x},${box.y},${box.w},${box.h}|${document.documentElement.dataset.theme || "dark"}`;
  if (mapLayer && mapKey === key) return;
  mapKey = key;
  if (!mapLayer) mapLayer = document.createElement("canvas");
  if (mapLayer.width !== canvas.width || mapLayer.height !== canvas.height) {
    mapLayer.width = canvas.width;
    mapLayer.height = canvas.height;
  }
  const g = mapLayer.getContext("2d");
  g.setTransform(1, 0, 0, 1, 0, 0);
  g.clearRect(0, 0, mapLayer.width, mapLayer.height);
  g.fillStyle = paint.sea;
  g.fillRect(0, 0, mapLayer.width, mapLayer.height);
  g.strokeStyle = paint.grid;
  g.lineWidth = 1;
  g.beginPath();
  for (let lon = -180; lon <= 180; lon += 30) {
    const x = project(lon, 0, box)[0];
    g.moveTo(x, box.y);
    g.lineTo(x, box.y + box.h);
  }
  for (let lat = -60; lat <= 60; lat += 30) {
    const y = project(0, lat, box)[1];
    g.moveTo(box.x, y);
    g.lineTo(box.x + box.w, y);
  }
  g.stroke();
  g.fillStyle = paint.land;
  g.strokeStyle = paint.stroke;
  g.lineWidth = 0.8;
  for (const feature of features) {
    g.beginPath();
    traceGeometry(feature.geometry, box, g);
    g.fill();
    g.stroke();
  }
}

function quad(a, c, b, t) {
  const u = 1 - t;
  return [
    u * u * a[0] + 2 * u * t * c[0] + t * t * b[0],
    u * u * a[1] + 2 * u * t * c[1] + t * t * b[1],
  ];
}

function spawn(now) {
  const origin = origins[originIndex % origins.length];
  const color = colors[originIndex % colors.length];
  originIndex += 1;
  flights.push({
    lon: origin[1],
    lat: origin[2],
    color,
    t0: now,
    dur: 980 + (originIndex % 6) * 160,
  });
  if (flights.length > 40) flights.splice(0, flights.length - 40);
}

function drawFlight(from, to, color, progress) {
  const mx = (from[0] + to[0]) / 2;
  const my = (from[1] + to[1]) / 2;
  const len = Math.hypot(to[0] - from[0], to[1] - from[1]) || 1;
  const lift = Math.min(90, len * 0.18);
  const control = [mx, my - lift];
  const steps = 28;
  const end = Math.max(2, Math.floor(steps * progress));
  ctx.beginPath();
  for (let i = 0; i <= end; i += 1) {
    const p = quad(from, control, to, i / steps);
    if (i === 0) ctx.moveTo(p[0], p[1]);
    else ctx.lineTo(p[0], p[1]);
  }
  ctx.strokeStyle = color;
  ctx.globalAlpha = 0.72;
  ctx.lineWidth = 1.6;
  ctx.stroke();
  const head = quad(from, control, to, progress);
  ctx.globalAlpha = 0.95;
  ctx.fillStyle = color;
  ctx.fillRect(head[0] - 2.2, head[1] - 2.2, 4.4, 4.4);
  ctx.globalAlpha = 1;
}

function frame(now) {
  resize();
  const box = viewBox();
  ensureMap(box);
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  if (mapLayer) ctx.drawImage(mapLayer, 0, 0);
  drawHostCountry(box);
  for (let i = 0; i < origins.length; i += 1) {
    const point = project(origins[i][1], origins[i][2], box);
    ctx.beginPath();
    ctx.fillStyle = i % 5 === 0 ? "#e07a3a" : "#c24b3c";
    ctx.globalAlpha = 0.45 + (i % 3) * 0.16;
    ctx.arc(point[0], point[1], 1.5 + (i % 3) * 0.7, 0, Math.PI * 2);
    ctx.fill();
  }
  ctx.globalAlpha = 1;
  const dest = project(target.lon, target.lat, box);
  if (!reduced) {
    if (now - spawnAt > 110) {
      spawnAt = now;
      spawn(now);
      if (originIndex % 3 === 0) spawn(now);
    }
    for (let i = flights.length - 1; i >= 0; i -= 1) {
      const flight = flights[i];
      const t = (now - flight.t0) / flight.dur;
      if (t >= 1) {
        impacts.push({ x: dest[0], y: dest[1], t0: now, color: flight.color });
        flights.splice(i, 1);
        continue;
      }
      const from = project(flight.lon, flight.lat, box);
      drawFlight(from, dest, flight.color, Math.min(1, t));
    }
    for (let i = impacts.length - 1; i >= 0; i -= 1) {
      const hit = impacts[i];
      const age = (now - hit.t0) / 700;
      if (age >= 1) {
        impacts.splice(i, 1);
        continue;
      }
      ctx.beginPath();
      ctx.strokeStyle = hit.color;
      ctx.globalAlpha = 1 - age;
      ctx.lineWidth = 1.2;
      ctx.arc(hit.x, hit.y, 4 + age * 16, 0, Math.PI * 2);
      ctx.stroke();
      ctx.globalAlpha = 1;
    }
  }
  if (!reduced) requestAnimationFrame(frame);
}

fetch("/world.geojson")
  .then((res) => res.ok ? res.json() : null)
  .then((data) => {
    features = data && data.features ? data.features : [];
    locateHost();
    mapKey = "";
    requestAnimationFrame(frame);
  })
  .catch(() => requestAnimationFrame(frame));
