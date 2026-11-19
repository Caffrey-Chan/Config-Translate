"use strict";

const element = (id) => document.getElementById(id);
const fileInput = element("source-file");
const fileStatus = element("file-status");
const form = element("mapping-form");
const interfaceBody = element("interface-rows");
const zoneBody = element("zone-rows");
const showAll = element("show-all");
const convertButton = element("convert");
const convertStatus = element("convert-status");
const result = element("result");
const preview = element("preview");

let config = null;
let conversion = null;
let interfaceRows = [];
let zoneRows = [];

function status(target, message, error = false) {
  target.textContent = message;
  target.classList.toggle("error", error);
  target.hidden = !message;
}

function encodeFile(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.addEventListener("load", () => resolve(reader.result.split(",", 2)[1]));
    reader.addEventListener("error", () => reject(new Error("无法读取选中的配置文件。")));
    reader.readAsDataURL(file);
  });
}

async function request(endpoint, payload) {
  let response;
  try {
    response = await fetch(endpoint, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload),
    });
  } catch {
    throw new Error("无法连接本地转换器。请确认程序仍在运行。");
  }
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || "转换请求失败。");
  }
  return data;
}

function mappingRow(body, item, detail, kind) {
  const row = body.insertRow();
  const sourceCell = document.createElement("th");
  sourceCell.scope = "row";
  const source = document.createElement("span");
  source.className = "source-name";
  source.textContent = item.name;
  sourceCell.append(source);
  if (detail) {
    const metadata = document.createElement("span");
    metadata.className = "detail";
    metadata.textContent = detail;
    sourceCell.append(metadata);
  }
  row.append(sourceCell);
  const field = document.createElement("input");
  field.type = "text";
  field.maxLength = 35;
  field.autocomplete = "off";
  field.spellcheck = false;
  field.setAttribute("aria-label", item.name + " 的 FortiGate 目标" + kind);
  row.insertCell().append(field);
  return {row, field, item};
}

function updateInterfaceRows() {
  const prioritizeRoutes = interfaceRows.some(({item}) => item.route_count > 0);
  let mapped = 0;
  for (const {row, field, item} of interfaceRows) {
    row.hidden = prioritizeRoutes && !showAll.checked && !item.route_count && !field.value.trim();
    if (field.value.trim()) {
      mapped++;
    }
  }
  element("mapping-summary").textContent = "已填写 " + mapped + " / " + interfaceRows.length + " 个接口";
}

function renderMappings(data) {
  interfaceBody.replaceChildren();
  zoneBody.replaceChildren();
  interfaceRows = data.interfaces.map((item) => {
    const details = [...item.ipv4];
    if (item.dhcp) details.push("DHCP");
    if (item.layer2) details.push("二层");
    if (item.aggregation_member) details.push("聚合组 " + item.aggregation_member + " 成员");
    if (item.route_count) details.push(item.route_count + " 条静态路由");
    return mappingRow(interfaceBody, item, details.join(" · "), "接口");
  });
  zoneRows = data.zones.map((name) => mappingRow(zoneBody, {name}, "", "区域"));
  showAll.checked = false;
  element("show-all-control").hidden = !(data.interfaces.some((item) => item.route_count)
                                        && data.interfaces.some((item) => !item.route_count));
  element("interface-table").hidden = !interfaceRows.length;
  element("no-interfaces").hidden = Boolean(interfaceRows.length);
  element("zone-panel").hidden = !zoneRows.length;
  element("zone-panel").open = false;
  updateInterfaceRows();
}

function clearResult() {
  conversion = null;
  result.hidden = true;
  preview.textContent = "";
  element("preview-panel").open = false;
}

fileInput.addEventListener("change", async () => {
  config = null;
  form.hidden = true;
  clearResult();
  status(convertStatus, "");
  const file = fileInput.files[0];
  if (!file) {
    status(fileStatus, "");
    return;
  }
  if (file.size === 0 || file.size > 16 * 1024 * 1024) {
    status(fileStatus, "请选择非空且不超过 16 MiB 的配置文件。", true);
    fileInput.value = "";
    return;
  }
  fileInput.disabled = true;
  status(fileStatus, "正在读取配置并识别接口…");
  try {
    const encoded = await encodeFile(file);
    const data = await request("/api/inspect", {config: encoded});
    renderMappings(data);
    config = encoded;
    form.hidden = false;
    const summary = "识别到 " + data.interfaces.length + " 个接口、"
                    + data.inventory.routes + " 条静态路由";
    status(fileStatus, summary + (data.version ? " · Comware " + data.version : ""));
  } catch (error) {
    fileInput.value = "";
    status(fileStatus, error.message, true);
  } finally {
    fileInput.disabled = false;
  }
});

showAll.addEventListener("change", updateInterfaceRows);
form.addEventListener("input", (event) => {
  if (event.target.type === "text") {
    clearResult();
    status(convertStatus, "");
    updateInterfaceRows();
  }
});

function collectMapping() {
  const targets = new Set();
  const entries = (rows) => rows.flatMap(({field, item}) => {
    const value = field.value.trim();
    if (!value) return [];
    const key = value.toLowerCase();
    if (!/^[A-Za-z0-9_.:-]{1,35}$/.test(value) || ["all", "any"].includes(key)) {
      field.focus();
      throw new Error(item.name + " 的目标名称无效。请使用字母、数字、下划线、点、冒号或连字符。");
    }
    if (targets.has(key)) {
      field.focus();
      throw new Error("目标名称 " + value + " 已被使用，请填写不同的接口或区域名。");
    }
    targets.add(key);
    return [[item.name, value]];
  });
  return {interfaces: Object.fromEntries(entries(interfaceRows)),
          zones: Object.fromEntries(entries(zoneRows))};
}

function renderResult(data) {
  const stats = element("result-stats");
  const cliRoutes = data.report.cli_entries["router static"] || 0;
  const cliPolicies = data.report.cli_entries["firewall policy"] || 0;
  stats.replaceChildren();
  for (const [label, value] of [
    ["路由草稿", cliRoutes],
    ["待复核路由", data.report.inventory.routes - cliRoutes],
    ["安全策略草稿", cliPolicies],
    ["待复核策略", data.report.inventory.policies - cliPolicies],
    ["NAT 复核项", data.report.inventory.nat_rules],
  ]) {
    const card = document.createElement("div");
    const title = document.createElement("dt");
    const count = document.createElement("dd");
    title.textContent = label;
    count.textContent = value;
    card.append(title, count);
    stats.append(card);
  }
  preview.textContent = data.cli || "本次没有生成 CLI 条目。";
  element("download-cli").disabled = !data.cli;
  result.hidden = false;
  result.scrollIntoView({block: "nearest"});
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!config) return;
  clearResult();
  let mapping;
  try {
    mapping = collectMapping();
  } catch (error) {
    status(convertStatus, error.message, true);
    return;
  }
  const fields = [fileInput, convertButton, ...[...interfaceRows, ...zoneRows].map(({field}) => field)];
  for (const field of fields) field.disabled = true;
  status(convertStatus, "正在按当前映射转换…");
  try {
    conversion = await request("/api/convert", {config, mapping});
    renderResult(conversion);
    status(convertStatus, "转换完成。");
  } catch (error) {
    status(convertStatus, error.message, true);
  } finally {
    for (const field of fields) field.disabled = false;
  }
});

function download(text, mediaType, filename) {
  const url = URL.createObjectURL(new Blob([text], {type: mediaType}));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

element("download-cli").addEventListener("click", () => {
  if (conversion?.cli) download(conversion.cli, "text/plain;charset=utf-8", "fortigate.cli");
});
element("download-report").addEventListener("click", () => {
  if (conversion) {
    download(JSON.stringify(conversion.report, null, 2) + "\n",
             "application/json;charset=utf-8", "migration.json");
  }
});
