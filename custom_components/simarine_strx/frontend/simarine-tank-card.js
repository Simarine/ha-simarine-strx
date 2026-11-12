/**
 * Simarine tank card: the STRx tank as the display. Filled to its level and
 * colored by tank type, with the level and the volume written inside it.
 *
 *   type: custom:simarine-tank-card
 *   entity: sensor.str2_8179_level    # Level sensor of the STRx device
 *   name: Fresh water tank            # optional, the device name otherwise
 *
 * The other values (volume, tank volume, tank type, status) come from the
 * sensors of the same device. Served and loaded by the Simarine STRx integration.
 */

const DOMAIN = "simarine_strx";
const CARD = "simarine-tank-card";

// Sensors of the device by translation key
const KEYS = ["level", "volume", "tank_volume_total", "tank_type", "status"];

// Liquid color by tank type, overridable from a theme, and the text color on top of it
const FILL = {
  fresh_water: ["var(--simarine-tank-fresh-water, #2b8fd6)", "#ffffff"],
  gray_water: ["var(--simarine-tank-gray-water, #8d979e)", "#ffffff"],
  black_water: ["var(--simarine-tank-black-water, #6d4c41)", "#ffffff"],
  fuel: ["var(--simarine-tank-fuel, #f2a900)", "#3b2a00"],
  other: ["var(--simarine-tank-other, #5eb0cf)", "#ffffff"],
};

// Tank in the 256 x 200 drawing, the scale left of it, the fill cap on top
const VIEW = { width: 256, height: 200 };
const TANK = { x: 48, y: 20, width: 196, height: 172, radius: 22 };
const CAP = { x: TANK.x + TANK.width / 2 - 20, y: 10, width: 40, height: 12, radius: 3 };
const CENTER = TANK.x + TANK.width / 2;

// Scale marks, fractions of the tank
const MARKS = [0.25, 0.5, 0.75];

// Wave height, and its period: the 2 x VIEW.width long wave drifts by one period
const AMPLITUDE = 3;
const PERIOD = 60;

const STYLE = `
  ha-card { padding: 12px 16px 16px; cursor: pointer; height: 100%; box-sizing: border-box;
            display: flex; flex-direction: column; }
  .header { display: flex; align-items: center; gap: 6px; margin-bottom: 8px; min-width: 0; }
  .name { font-size: 1.1em; font-weight: 500; color: var(--primary-text-color);
          white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .type { color: var(--secondary-text-color); white-space: nowrap; }
  .status { margin-left: auto; display: flex; align-items: center; gap: 6px; flex: 0 0 auto;
            color: var(--secondary-text-color); font-size: 0.9em; }
  .dot { width: 9px; height: 9px; border-radius: 50%; background: var(--disabled-text-color, #bdbdbd); }
  .dot.ok { background: var(--success-color, #43a047); }
  .dot.attention { background: var(--warning-color, #ffa600); }
  svg { display: block; width: 100%; height: auto; flex: 1 1 auto; min-height: 0; max-height: 320px;
        font-family: inherit; }
  .shell { fill: var(--secondary-background-color, #eef1f4); }
  .cap { fill: var(--divider-color, #c9d0d6); }
  .outline { fill: none; stroke: var(--divider-color, #c9d0d6); stroke-width: 3; }
  .unknown .outline { stroke-dasharray: 8 6; }
  .wave { animation: drift 7s linear infinite; }
  @keyframes drift { from { transform: translateX(0); } to { transform: translateX(-${PERIOD}px); } }
  @media (prefers-reduced-motion: reduce) { .wave { animation: none; } }
  .mark { stroke: var(--primary-text-color); stroke-width: 1.5; opacity: 0.3; }
  .mark-label { fill: var(--secondary-text-color); font-size: 10px; text-anchor: end; }
  .level { font-size: 44px; font-weight: 500; text-anchor: middle; dominant-baseline: central; }
  .volume { font-size: 17px; text-anchor: middle; dominant-baseline: central; }
  .dry text { fill: var(--primary-text-color); }
  .dry .volume { fill: var(--secondary-text-color); }
`;

class SimarineTankCard extends HTMLElement {
  static getStubConfig(hass) {
    const level = Object.values(hass.entities || {}).find(
      (entry) => entry.platform === DOMAIN && entry.translation_key === "level",
    );
    return { entity: level ? level.entity_id : "" };
  }

  setConfig(config) {
    if (!config || !config.entity) {
      throw new Error("Set entity to the Level sensor of an STRx device");
    }
    this._config = config;
    this._signature = undefined;
    this._update();
  }

  set hass(hass) {
    this._hass = hass;
    this._update();
  }

  getCardSize() {
    return 5;
  }

  getGridOptions() {
    return { columns: 6, rows: 4, min_columns: 4, min_rows: 3 };
  }

  // Structure, built once

  _build() {
    const root = this.attachShadow({ mode: "open" });
    const { x, y, width, height, radius } = TANK;
    const tank = `x="${x}" y="${y}" width="${width}" height="${height}" rx="${radius}"`;
    const readout = (cls) => `
      <g class="${cls}">
        <text class="level" x="${CENTER}" y="${y + height * 0.44}"></text>
        <text class="volume" x="${CENTER}" y="${y + height * 0.44 + 38}"></text>
      </g>`;
    root.innerHTML = `
      <style>${STYLE}</style>
      <ha-card>
        <div class="header">
          <span class="name"></span><span class="type"></span>
          <span class="status"><span class="status-text"></span><span class="dot"></span></span>
        </div>
        <svg viewBox="0 0 ${VIEW.width} ${VIEW.height}" role="img">
          <defs>
            <clipPath id="inside"><rect ${tank}></rect></clipPath>
            <clipPath id="wet"><rect class="wet" x="0" width="${VIEW.width}"></rect></clipPath>
          </defs>
          <rect class="cap" x="${CAP.x}" y="${CAP.y}" width="${CAP.width}" height="${CAP.height}" rx="${CAP.radius}"></rect>
          <rect class="shell" ${tank}></rect>
          <g clip-path="url(#inside)">
            <rect class="body" x="0" width="${VIEW.width}"></rect>
            <path class="wave" d=""></path>
          </g>
          ${MARKS.map((f) => {
            const my = y + height * (1 - f);
            return `<line class="mark" x1="${x - 4}" x2="${x + 10}" y1="${my}" y2="${my}"></line>
              <text class="mark-label" x="${x - 8}" y="${my}" dominant-baseline="central"></text>`;
          }).join("")}
          ${readout("dry")}
          <g clip-path="url(#wet)">${readout("wet")}</g>
          <rect class="outline" ${tank}></rect>
        </svg>
      </ha-card>`;
    root.querySelector("ha-card").addEventListener("click", () => this._moreInfo());
  }

  // Values, written on every change

  _update() {
    const hass = this._hass;
    if (!hass || !this._config) {
      return;
    }
    const ids = this._entities();
    const states = Object.fromEntries(KEYS.map((key) => [key, ids[key] ? hass.states[ids[key]] : undefined]));
    const signature = JSON.stringify([
      this._config,
      KEYS.map((key) => states[key] && [states[key].state, states[key].attributes.unit_of_measurement]),
      hass.locale && hass.locale.language,
    ]);
    if (signature === this._signature) {
      return;
    }
    this._signature = signature;
    if (!this.shadowRoot) {
      this._build();
    }
    const root = this.shadowRoot;

    const level = states.level ? parseFloat(states.level.state) : NaN;
    const known = Number.isFinite(level);
    const fraction = known ? Math.min(Math.max(level / 100, 0), 1) : 0;
    const [liquid, onLiquid] = FILL[states.tank_type && states.tank_type.state] || FILL.other;
    const total = this._known(states.tank_volume_total) ? parseFloat(states.tank_volume_total.state) : NaN;

    // Header
    root.querySelector(".name").textContent = this._config.name || this._deviceName(ids.level) || "STRx";
    root.querySelector(".type").textContent = this._known(states.tank_type) ? `· ${this._format(states.tank_type)}` : "";
    const status = states.status;
    root.querySelector(".dot").className =
      "dot" + (!this._known(status) ? "" : status.state === "ok" ? " ok" : " attention");
    root.querySelector(".status-text").textContent = status && status.state !== "ok" ? this._format(status) : "";
    root.querySelector(".status").title = status ? this._format(status) : "";

    // Readout, written twice: over the empty part and, clipped, over the liquid
    const levelText = known ? this._format(states.level) : "—";
    let volumeText = "";
    if (this._known(states.volume) && Number.isFinite(total)) {
      volumeText = `${this._format(states.volume)} / ${this._format(states.tank_volume_total)}`;
    } else if (this._known(states.volume)) {
      volumeText = this._format(states.volume);
    } else if (Number.isFinite(total)) {
      volumeText = `— / ${this._format(states.tank_volume_total)}`;
    }
    root.querySelectorAll(".level").forEach((node) => (node.textContent = levelText));
    root.querySelectorAll(".volume").forEach((node) => (node.textContent = volumeText));
    root.querySelectorAll(".wet text").forEach((node) => node.setAttribute("fill", onLiquid));

    // Scale in liters once the tank volume is known, in percent otherwise
    root.querySelectorAll(".mark-label").forEach((node, i) => {
      const f = MARKS[i];
      node.textContent = Number.isFinite(total) ? `${Math.round(total * f)} L` : `${f * 100} %`;
    });

    const svg = root.querySelector("svg");
    svg.classList.toggle("unknown", !known);
    svg.setAttribute("aria-label", [levelText, volumeText].filter(Boolean).join(", "));
    this._drawLiquid(fraction, liquid);
  }

  _drawLiquid(fraction, color) {
    const root = this.shadowRoot;
    const { y, height } = TANK;
    const bottom = y + height;
    const surface = bottom - height * fraction;
    const body = root.querySelector(".body");
    const wave = root.querySelector(".wave");
    const wet = root.querySelector(".wet");
    body.setAttribute("fill", color);
    wave.setAttribute("fill", color);
    wet.setAttribute("y", surface);
    wet.setAttribute("height", Math.max(VIEW.height - surface, 0));

    if (fraction <= 0 || fraction >= 1) {
      // Empty or full: a flat surface
      body.setAttribute("y", surface);
      body.setAttribute("height", Math.max(bottom - surface, 0));
      wave.setAttribute("d", "");
      return;
    }
    // The body starts below the troughs of the wave on top of it
    body.setAttribute("y", surface + AMPLITUDE);
    body.setAttribute("height", Math.max(bottom - surface - AMPLITUDE, 0));
    const half = PERIOD / 2;
    let d = `M 0 ${surface} q ${half / 2} ${-2 * AMPLITUDE} ${half} 0`;
    for (let px = half; px < 2 * VIEW.width; px += half) {
      d += ` t ${half} 0`;
    }
    d += ` V ${surface + AMPLITUDE + 1} H 0 Z`;
    wave.setAttribute("d", d);
  }

  // Helpers

  _entities() {
    const entities = this._hass.entities || {};
    const own = entities[this._config.entity];
    const ids = {};
    if (own && own.device_id) {
      for (const entry of Object.values(entities)) {
        if (entry.device_id === own.device_id && entry.platform === DOMAIN && KEYS.includes(entry.translation_key)) {
          ids[entry.translation_key] = entry.entity_id;
        }
      }
    }
    // The configured entity is the level, whatever the registry says
    ids.level = this._config.entity;
    return ids;
  }

  _deviceName(entityId) {
    const entry = (this._hass.entities || {})[entityId];
    const device = entry && entry.device_id && (this._hass.devices || {})[entry.device_id];
    return device ? device.name_by_user || device.name : undefined;
  }

  _known(stateObj) {
    return Boolean(stateObj) && !["unknown", "unavailable"].includes(stateObj.state);
  }

  _format(stateObj) {
    if (typeof this._hass.formatEntityState === "function") {
      return this._hass.formatEntityState(stateObj);
    }
    const unit = stateObj.attributes.unit_of_measurement;
    return unit ? `${stateObj.state} ${unit}` : stateObj.state;
  }

  _moreInfo() {
    const event = new Event("hass-more-info", { bubbles: true, composed: true });
    event.detail = { entityId: this._config.entity };
    this.dispatchEvent(event);
  }
}

if (!customElements.get(CARD)) {
  customElements.define(CARD, SimarineTankCard);
  window.customCards = window.customCards || [];
  window.customCards.push({
    type: CARD,
    name: "Simarine tank",
    description: "STRx tank filled to its level, colored by tank type, with level and volume inside",
    preview: true,
    documentationURL: "https://github.com/Simarine/ha-simarine-strx",
  });
}
