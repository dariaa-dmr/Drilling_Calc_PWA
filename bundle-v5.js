/* DrillingCalc PWA clean bundle v5 */
(() => {
  "use strict";

  const PACKAGE_FORMAT = "drillcalc-encrypted-package";
  const VAULT_FORMAT = "drillcalc-local-vault";
  const VERSION = 1;
  const DEFAULT_ITERATIONS = 210000;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  function cryptoApi() {
    if (!globalThis.crypto?.subtle) throw new Error("Web Crypto API недоступен");
    return globalThis.crypto;
  }

  function toBase64(bytes) {
    if (typeof Buffer !== "undefined") return Buffer.from(bytes).toString("base64");
    let binary = "";
    const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (let i = 0; i < view.length; i += 1) binary += String.fromCharCode(view[i]);
    return btoa(binary);
  }

  function fromBase64(value) {
    if (typeof Buffer !== "undefined") return new Uint8Array(Buffer.from(value, "base64"));
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function randomBytes(length) {
    const bytes = new Uint8Array(length);
    cryptoApi().getRandomValues(bytes);
    return bytes;
  }

  async function deriveKey(secret, salt, iterations = DEFAULT_ITERATIONS) {
    if (typeof secret !== "string" || secret.length < 6) throw new Error("Код должен содержать не менее 6 символов");
    const material = await cryptoApi().subtle.importKey(
      "raw",
      encoder.encode(secret),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return cryptoApi().subtle.deriveKey(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function encryptObject(object, secret, format, iterations = DEFAULT_ITERATIONS) {
    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const key = await deriveKey(secret, salt, iterations);
    const aad = encoder.encode(`${format}:v${VERSION}`);
    const plaintext = encoder.encode(JSON.stringify(object));
    const encrypted = await cryptoApi().subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
      key,
      plaintext
    );
    return {
      format,
      version: VERSION,
      kdf: {
        name: "PBKDF2",
        hash: "SHA-256",
        iterations,
        salt: toBase64(salt)
      },
      cipher: {
        name: "AES-GCM",
        iv: toBase64(iv),
        tag_length: 128
      },
      payload: toBase64(new Uint8Array(encrypted))
    };
  }

  async function decryptObject(container, secret, expectedFormat) {
    if (!container || container.format !== expectedFormat || container.version !== VERSION) {
      throw new Error("Неподдерживаемый или повреждённый файл");
    }
    if (container.kdf?.name !== "PBKDF2" || container.cipher?.name !== "AES-GCM") {
      throw new Error("Неподдерживаемый формат шифрования");
    }
    const salt = fromBase64(container.kdf.salt);
    const iv = fromBase64(container.cipher.iv);
    const ciphertext = fromBase64(container.payload);
    const key = await deriveKey(secret, salt, Number(container.kdf.iterations));
    const aad = encoder.encode(`${expectedFormat}:v${VERSION}`);
    try {
      const decrypted = await cryptoApi().subtle.decrypt(
        { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
        key,
        ciphertext
      );
      return { value: JSON.parse(decoder.decode(decrypted)), key };
    } catch {
      throw new Error("Неверный код или файл повреждён");
    }
  }

  async function createPackage(payload, password) {
    return encryptObject(payload, password, PACKAGE_FORMAT);
  }

  async function openPackage(container, password) {
    return (await decryptObject(container, password, PACKAGE_FORMAT)).value;
  }

  async function createVault(payload, localCode) {
    return encryptObject(payload, localCode, VAULT_FORMAT);
  }

  async function openVault(container, localCode) {
    return decryptObject(container, localCode, VAULT_FORMAT);
  }

  async function encryptVaultWithKey(payload, existingContainer, key) {
    if (!existingContainer || existingContainer.format !== VAULT_FORMAT) throw new Error("Локальное хранилище повреждено");
    const iv = randomBytes(12);
    const aad = encoder.encode(`${VAULT_FORMAT}:v${VERSION}`);
    const encrypted = await cryptoApi().subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
      key,
      encoder.encode(JSON.stringify(payload))
    );
    return {
      ...existingContainer,
      cipher: { ...existingContainer.cipher, iv: toBase64(iv) },
      payload: toBase64(new Uint8Array(encrypted))
    };
  }

  function serialize(container) {
    return JSON.stringify(container, null, 2);
  }

  function parse(text) {
    try { return JSON.parse(text); }
    catch { throw new Error("Файл не является корректным JSON-контейнером"); }
  }

  const api = {
    PACKAGE_FORMAT,
    VAULT_FORMAT,
    VERSION,
    createPackage,
    openPackage,
    createVault,
    openVault,
    encryptVaultWithKey,
    serialize,
    parse,
    toBase64,
    fromBase64
  };

  globalThis.CryptoVault = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})();

(() => {
  "use strict";

  const asNumber = (value, label, options = {}) => {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) throw new Error(`${label}: требуется число`);
    if (options.positive && parsed <= 0) throw new Error(`${label}: значение должно быть больше нуля`);
    if (options.min !== undefined && parsed < options.min) throw new Error(`${label}: минимум ${options.min}`);
    if (options.max !== undefined && parsed > options.max) throw new Error(`${label}: максимум ${options.max}`);
    return parsed;
  };

  const findDiameterRange = (catalog, diameter) => catalog.diameters.find(
    (row) => diameter >= Number(row.from) && diameter <= Number(row.to)
  );

  const legalMinimum = (catalog, maxDiameter) => {
    const rows = catalog.diameters
      .filter((row) => Number(row.from) <= maxDiameter && row.min_order !== null && row.min_order !== "" && Number(row.min_order) > 0)
      .sort((a, b) => Number(a.from) - Number(b.from));
    return rows.length ? Number(rows.at(-1).min_order) : 0;
  };

  function validateCatalog(catalog) {
    const errors = [];
    const rules = catalog.rules || {};
    for (const [key, label] of Object.entries({
      km_price_per_km: "Стоимость километра",
      physical_minimum_wet: "Минимальная сумма мокрого сверления",
      physical_minimum_dry: "Минимальная сумма сухого сверления",
      max_discount_percent: "Максимальная скидка"
    })) {
      if (!Number.isFinite(Number(rules[key])) || Number(rules[key]) < 0) errors.push(`${label}: неверное значение`);
    }
    const names = (rows, label) => {
      const seen = new Set();
      rows.forEach((row, index) => {
        const value = String(row.name || "").trim();
        if (!value) errors.push(`${label}, строка ${index + 1}: пустое название`);
        const key = value.toLocaleLowerCase("ru");
        if (value && seen.has(key)) errors.push(`${label}: повтор названия «${value}»`);
        seen.add(key);
      });
    };

    const ranges = [...catalog.diameters].sort((a, b) => Number(a.from) - Number(b.from));
    ranges.forEach((row, index) => {
      const from = Number(row.from);
      const to = Number(row.to);
      if (!Number.isFinite(from) || !Number.isFinite(to) || from <= 0 || to <= 0) errors.push(`Диаметры, строка ${index + 1}: неверные границы`);
      if (from > to) errors.push(`Диаметры, строка ${index + 1}: начало больше конца`);
      if (Number(row.concrete_price) < 0 || Number(row.brick_price) < 0) errors.push(`Диаметры, строка ${index + 1}: цена не может быть отрицательной`);
      if (index > 0 && Number(ranges[index - 1].to) >= from) errors.push(`Диапазоны ${ranges[index - 1].from}–${ranges[index - 1].to} и ${from}–${to} пересекаются`);
    });

    names(catalog.coefficients, "Коэффициенты");
    catalog.coefficients.forEach((row, index) => {
      if (!Number.isFinite(Number(row.value)) || Number(row.value) < 1) errors.push(`Коэффициенты, строка ${index + 1}: множитель должен быть не меньше 1`);
    });

    names(catalog.services, "Услуги");
    catalog.services.forEach((row, index) => {
      if (!Number.isFinite(Number(row.price_per_unit)) || Number(row.price_per_unit) < 0) errors.push(`Услуги, строка ${index + 1}: неверная цена`);
      if (!String(row.unit || "").trim()) errors.push(`Услуги, строка ${index + 1}: не указана единица`);
    });

    names(catalog.fees, "Наценки");
    catalog.fees.forEach((row, index) => {
      if (!Number.isFinite(Number(row.price)) || Number(row.price) < 0) errors.push(`Наценки, строка ${index + 1}: неверная цена`);
    });

    return errors;
  }

  function calculateHole(catalog, hole, index) {
    const diameter = asNumber(hole.diameter, `Отверстие №${index + 1}, диаметр`, { positive: true });
    const depth = asNumber(hole.depth, `Отверстие №${index + 1}, глубина`, { positive: true });
    const range = findDiameterRange(catalog, diameter);
    if (!range) throw new Error(`Отверстие №${index + 1}: диаметр ${diameter} мм отсутствует в прайсе`);
    const material = hole.material === "кирпич" ? "кирпич" : "бетон";
    const pricePerCm = material === "бетон" ? Number(range.concrete_price) : Number(range.brick_price);
    const baseCost = pricePerCm * depth;

    let extraPercent = 0;
    const coefficientLines = [];
    for (const id of hole.coefficient_ids || []) {
      const item = catalog.coefficients.find((row) => row.id === id);
      if (!item) throw new Error(`Коэффициент не найден: ${id}`);
      const percent = (Number(item.value) - 1) * 100;
      extraPercent += percent;
      coefficientLines.push({ id: item.id, name: item.name, percent });
    }
    const coefficientSurcharge = baseCost * extraPercent / 100;

    let servicesCost = 0;
    const serviceLines = [];
    for (const [id, rawQty] of Object.entries(hole.services || {})) {
      const item = catalog.services.find((row) => row.id === id && row.is_per_hole);
      if (!item) throw new Error(`Услуга для отверстия не найдена: ${id}`);
      const qty = asNumber(rawQty, `Количество услуги «${item.name}»`, { positive: true });
      const cost = Number(item.price_per_unit) * qty;
      servicesCost += cost;
      serviceLines.push({ id: item.id, name: item.name, unit: item.unit, qty, price: Number(item.price_per_unit), cost });
    }

    return {
      diameter,
      depth,
      material,
      drilling_type: hole.drilling_type === "dry" ? "dry" : "wet",
      price_per_cm: pricePerCm,
      base_cost: baseCost,
      coefficients: coefficientLines,
      extra_percent: extraPercent,
      coefficient_surcharge: coefficientSurcharge,
      services: serviceLines,
      services_cost: servicesCost,
      total: baseCost + coefficientSurcharge + servicesCost
    };
  }

  function calculateOrder(catalog, payload) {
    const catalogErrors = validateCatalog(catalog);
    if (catalogErrors.length) throw new Error(`Ошибка справочника: ${catalogErrors[0]}`);
    if (!Array.isArray(payload.holes) || payload.holes.length === 0) throw new Error("Добавьте хотя бы одно отверстие");

    const holes = payload.holes.map((hole, index) => calculateHole(catalog, hole, index));
    const rawByType = { wet: 0, dry: 0 };
    holes.forEach((hole) => { rawByType[hole.drilling_type] += hole.total; });

    const clientType = payload.client_type === "юрлицо" ? "юрлицо" : "физлицо";
    const adjustedByType = { ...rawByType };
    let minimumValue = 0;
    let minimumAdjustment = 0;
    let minimumLabel = "";

    if (clientType === "физлицо") {
      const physicalMinimums = { wet: Number(catalog.rules.physical_minimum_wet), dry: Number(catalog.rules.physical_minimum_dry) };
      for (const [type, minimum] of Object.entries(physicalMinimums)) {
        if (adjustedByType[type] > 0 && adjustedByType[type] < minimum) {
          minimumAdjustment += minimum - adjustedByType[type];
          adjustedByType[type] = minimum;
        }
      }
      minimumLabel = "Минимальная сумма для физлица по типу сверления";
    } else {
      const maxDiameter = Math.max(...holes.map((hole) => hole.diameter));
      minimumValue = legalMinimum(catalog, maxDiameter);
      const rawTotal = rawByType.wet + rawByType.dry;
      if (minimumValue > rawTotal) minimumAdjustment = minimumValue - rawTotal;
      minimumLabel = `Минимальная сумма для юрлица, максимальный диаметр ${maxDiameter} мм`;
    }

    const rawHolesTotal = rawByType.wet + rawByType.dry;
    const adjustedHolesTotal = clientType === "физлицо"
      ? adjustedByType.wet + adjustedByType.dry
      : rawHolesTotal + minimumAdjustment;

    let orderServicesCost = 0;
    const orderServiceLines = [];
    for (const [id, rawQty] of Object.entries(payload.order_services || {})) {
      const item = catalog.services.find((row) => row.id === id && !row.is_per_hole);
      if (!item) throw new Error(`Общая услуга не найдена: ${id}`);
      const qty = asNumber(rawQty, `Количество услуги «${item.name}»`, { positive: true });
      const cost = Number(item.price_per_unit) * qty;
      orderServicesCost += cost;
      orderServiceLines.push({ id: item.id, name: item.name, unit: item.unit, qty, price: Number(item.price_per_unit), cost });
    }

    let feesCost = 0;
    const feeLines = [];
    for (const id of payload.fee_ids || []) {
      const item = catalog.fees.find((row) => row.id === id);
      if (!item) throw new Error(`Наценка не найдена: ${id}`);
      feesCost += Number(item.price);
      feeLines.push({ id: item.id, name: item.name, cost: Number(item.price) });
    }

    const km = asNumber(payload.km || 0, "Километраж", { min: 0 });
    const discount = asNumber(payload.discount || 0, "Скидка", { min: 0, max: Number(catalog.rules.max_discount_percent) });
    const kmCost = km * Number(catalog.rules.km_price_per_km);
    const subtotalBeforeDiscount = adjustedHolesTotal + orderServicesCost + feesCost + kmCost;
    const discountAmount = subtotalBeforeDiscount * discount / 100;

    return {
      created_at: new Date().toISOString(),
      client_type: clientType,
      holes,
      raw_by_type: rawByType,
      adjusted_by_type: adjustedByType,
      raw_holes_total: rawHolesTotal,
      adjusted_holes_total: adjustedHolesTotal,
      minimum: { value: minimumValue, adjustment: minimumAdjustment, label: minimumLabel },
      order_services: orderServiceLines,
      order_services_cost: orderServicesCost,
      fees: feeLines,
      fees_cost: feesCost,
      km,
      km_cost: kmCost,
      discount_percent: discount,
      subtotal_before_discount: subtotalBeforeDiscount,
      discount_amount: discountAmount,
      total: subtotalBeforeDiscount - discountAmount
    };
  }

  const api = { asNumber, findDiameterRange, legalMinimum, validateCatalog, calculateOrder };
  globalThis.DrillingLogic = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})();

(() => {
  "use strict";

  const DB_NAME = "drilling_calc_secure_v4";
  const DB_VERSION = 1;
  const STORE = "secure_app";

  function openDb() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("Не удалось открыть локальное хранилище"));
    });
  }

  async function get(key) {
    const db = await openDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly");
      const request = tx.objectStore(STORE).get(key);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
      tx.oncomplete = () => db.close();
    });
  }

  async function set(key, value) {
    const db = await openDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put(structuredClone(value), key);
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => { db.close(); reject(tx.error); };
      tx.onabort = () => { db.close(); reject(tx.error || new Error("Запись отменена")); };
    });
  }

  async function remove(key) {
    const db = await openDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).delete(key);
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => { db.close(); reject(tx.error); };
    });
  }

  async function requestPersistence() {
    if (!navigator.storage?.persist) return { supported: false, persisted: false };
    try {
      const already = navigator.storage.persisted ? await navigator.storage.persisted() : false;
      const persisted = already || await navigator.storage.persist();
      return { supported: true, persisted };
    } catch {
      return { supported: true, persisted: false };
    }
  }

  globalThis.SecureStorage = { get, set, remove, requestPersistence };
})();

(() => {
  "use strict";

  const textEncoder = new TextEncoder();
  const xmlEscape = (value) => String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");

  const crcTable = (() => {
    const table = new Uint32Array(256);
    for (let n = 0; n < 256; n += 1) {
      let c = n;
      for (let k = 0; k < 8; k += 1) c = (c & 1) ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      table[n] = c >>> 0;
    }
    return table;
  })();

  function crc32(bytes) {
    let crc = 0xffffffff;
    for (const byte of bytes) crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
    return (crc ^ 0xffffffff) >>> 0;
  }

  const u16 = (value) => new Uint8Array([value & 0xff, (value >>> 8) & 0xff]);
  const u32 = (value) => new Uint8Array([value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff]);
  const concat = (parts) => {
    const size = parts.reduce((sum, part) => sum + part.length, 0);
    const out = new Uint8Array(size);
    let offset = 0;
    parts.forEach((part) => { out.set(part, offset); offset += part.length; });
    return out;
  };

  function makeZip(files) {
    const localParts = [];
    const centralParts = [];
    let offset = 0;

    for (const file of files) {
      const name = textEncoder.encode(file.name);
      const bytes = typeof file.data === "string" ? textEncoder.encode(file.data) : file.data;
      const crc = crc32(bytes);
      const local = concat([
        u32(0x04034b50), u16(20), u16(0x0800), u16(0), u16(0), u16(0),
        u32(crc), u32(bytes.length), u32(bytes.length), u16(name.length), u16(0), name, bytes
      ]);
      localParts.push(local);

      const central = concat([
        u32(0x02014b50), u16(20), u16(20), u16(0x0800), u16(0), u16(0), u16(0),
        u32(crc), u32(bytes.length), u32(bytes.length), u16(name.length), u16(0), u16(0),
        u16(0), u16(0), u32(0), u32(offset), name
      ]);
      centralParts.push(central);
      offset += local.length;
    }

    const centralSize = centralParts.reduce((sum, part) => sum + part.length, 0);
    const end = concat([
      u32(0x06054b50), u16(0), u16(0), u16(files.length), u16(files.length),
      u32(centralSize), u32(offset), u16(0)
    ]);
    return concat([...localParts, ...centralParts, end]);
  }

  function columnName(index) {
    let result = "";
    let value = index + 1;
    while (value > 0) {
      value -= 1;
      result = String.fromCharCode(65 + (value % 26)) + result;
      value = Math.floor(value / 26);
    }
    return result;
  }

  function cellXml(value, row, column, style = 0) {
    const ref = `${columnName(column)}${row}`;
    if (typeof value === "number" && Number.isFinite(value)) return `<c r="${ref}" s="${style}"><v>${value}</v></c>`;
    return `<c r="${ref}" t="inlineStr" s="${style}"><is><t xml:space="preserve">${xmlEscape(value)}</t></is></c>`;
  }

  function worksheetXml(rows) {
    const rowXml = rows.map((row, rowIndex) => {
      const cells = row.map((cell, columnIndex) => {
        const normalized = (cell && typeof cell === "object" && !Array.isArray(cell)) ? cell : { value: cell };
        return cellXml(normalized.value, rowIndex + 1, columnIndex, normalized.style || 0);
      }).join("");
      return `<row r="${rowIndex + 1}">${cells}</row>`;
    }).join("");
    return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><cols><col min="1" max="1" width="34" customWidth="1"/><col min="2" max="8" width="20" customWidth="1"/></cols><sheetData>${rowXml}</sheetData></worksheet>`;
  }

  function buildRows(payload, details) {
    const rows = [
      [{ value: "Расчёт стоимости алмазного бурения", style: 2 }],
      ["Дата", new Date(details.created_at).toLocaleString("ru-RU")],
      ["Тип клиента", details.client_type],
      ["Километраж, км", details.km],
      ["Скидка, %", details.discount_percent],
      [],
      [{ value: "Отверстия", style: 1 }],
      [
        { value: "№", style: 1 }, { value: "Диаметр, мм", style: 1 }, { value: "Глубина, см", style: 1 },
        { value: "Материал", style: 1 }, { value: "Тип", style: 1 }, { value: "Условия", style: 1 },
        { value: "Услуги", style: 1 }, { value: "Сумма", style: 1 }
      ]
    ];

    details.holes.forEach((hole, index) => {
      const conditions = hole.coefficients.map((item) => item.name).join("; ");
      const services = hole.services.map((item) => `${item.name}: ${item.qty} ${item.unit}`).join("; ");
      rows.push([
        index + 1,
        hole.diameter,
        hole.depth,
        hole.material,
        hole.drilling_type === "dry" ? "Сухое" : "Мокрое",
        conditions,
        services,
        hole.total
      ]);
    });

    if (details.order_services.length) {
      rows.push([], [{ value: "Общие услуги", style: 1 }]);
      details.order_services.forEach((item) => rows.push([item.name, `${item.qty} ${item.unit}`, item.cost]));
    }
    if (details.fees.length) {
      rows.push([], [{ value: "Разовые наценки", style: 1 }]);
      details.fees.forEach((item) => rows.push([item.name, item.cost]));
    }
    rows.push(
      [],
      ["Стоимость работ", details.adjusted_holes_total],
      ["Общие услуги", details.order_services_cost],
      ["Километраж", details.km_cost],
      ["Разовые наценки", details.fees_cost],
      ["Сумма до скидки", details.subtotal_before_discount],
      ["Скидка", -details.discount_amount],
      [{ value: "ИТОГО", style: 2 }, { value: details.total, style: 2 }]
    );
    return rows;
  }

  function createWorkbook(payload, details) {
    const sheet = worksheetXml(buildRows(payload, details));
    const now = new Date().toISOString();
    const files = [
      { name: "[Content_Types].xml", data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>` },
      { name: "_rels/.rels", data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>` },
      { name: "docProps/core.xml", data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>Расчёт бурения</dc:title><dc:creator>Калькулятор бурения</dc:creator><dcterms:created xsi:type="dcterms:W3CDTF">${now}</dcterms:created></cp:coreProperties>` },
      { name: "docProps/app.xml", data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>Калькулятор бурения</Application></Properties>` },
      { name: "xl/workbook.xml", data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Расчёт" sheetId="1" r:id="rId1"/></sheets></workbook>` },
      { name: "xl/_rels/workbook.xml.rels", data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>` },
      { name: "xl/styles.xml", data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="3"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="14"/><name val="Calibri"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border/></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="2" fillId="0" borderId="0" xfId="0"/></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>` },
      { name: "xl/worksheets/sheet1.xml", data: sheet }
    ];
    return new Blob([makeZip(files)], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" });
  }

  async function saveWorkbook(payload, details) {
    const blob = createWorkbook(payload, details);
    const filename = `raschet_bureniya_${new Date().toISOString().slice(0, 10)}.xlsx`;
    const file = new File([blob], filename, { type: blob.type });
    if (navigator.canShare && navigator.canShare({ files: [file] })) {
      await navigator.share({ files: [file], title: "Расчёт бурения" });
      return;
    }
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  const api = { makeZip, createWorkbook, saveWorkbook, buildRows };
  globalThis.XlsxExport = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})();

(() => {
  "use strict";

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const uid = (prefix) => `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  const money = (value) => `${new Intl.NumberFormat("ru-RU", { maximumFractionDigits: 2 }).format(Number(value || 0))} руб.`;
  const clone = (value) => JSON.parse(JSON.stringify(value));

  let vaultContainer = null;
  let vaultKey = null;
  let state = null;
  let catalog = null;
  let draft = null;
  let lastCalculation = null;
  let saveTimer = null;
  let toastTimer = null;
  let lockTimer = null;
  let hiddenTimer = null;
  let unlockFailures = 0;
  let blockedUntil = 0;

  const emptyHole = () => ({
    id: uid("hole"), diameter: "", depth: "", material: "бетон", drilling_type: "wet",
    coefficient_ids: catalog ? catalog.coefficients.filter((item) => item.default_checked).map((item) => item.id) : [],
    services: {}
  });
  const emptyDraft = () => ({ holes: [emptyHole()], order_services: {}, fee_ids: [], km: 0, client_type: "физлицо", discount: 0 });

  function showOnly(id) {
    ["loadingScreen", "activationScreen", "lockScreen", "app"].forEach((name) => { $(`#${name}`).hidden = name !== id; });
  }

  function showToast(message, timeout = 2800) {
    const toast = $("#toast");
    toast.textContent = message;
    toast.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { toast.hidden = true; }, timeout);
  }

  function setSaveState(text) { $("#saveState").textContent = text; }

  function applyTheme() {
    const theme = state?.preferences?.theme || localStorage.getItem("drill-theme") || "system";
    const dark = theme === "dark" || (theme === "system" && matchMedia("(prefers-color-scheme: dark)").matches);
    document.body.classList.toggle("dark", dark);
  }

  async function readJsonFile(file) {
    if (!file) throw new Error("Выберите файл");
    return CryptoVault.parse(await file.text());
  }

  function validatePackagePayload(payload) {
    if (!payload || payload.schema_version !== 1 || !payload.catalog) throw new Error("Неверная структура конфигурации");
    const errors = DrillingLogic.validateCatalog(payload.catalog);
    if (errors.length) throw new Error(`Ошибка прайса: ${errors[0]}`);
    if (!String(payload.client?.name || "").trim()) throw new Error("В конфигурации не указано имя клиента");
    if (!String(payload.package_version || "").trim()) throw new Error("В конфигурации не указана версия");
    if (payload.expires_at && new Date(payload.expires_at) < new Date()) throw new Error("Срок действия конфигурации истёк");
    return payload;
  }

  function newStateFromPackage(payload) {
    return {
      schema_version: 1,
      client: payload.client,
      package_version: payload.package_version,
      issued_at: payload.issued_at || new Date().toISOString(),
      expires_at: payload.expires_at || null,
      options: payload.options || {},
      catalog: clone(payload.catalog),
      draft: null,
      preferences: { theme: "system", auto_lock_minutes: Number(payload.options?.auto_lock_minutes || 5) }
    };
  }

  async function persistState(immediate = false) {
    if (!vaultContainer || !vaultKey || !state) return;
    state.draft = draft;
    const save = async () => {
      setSaveState("Сохранение…");
      vaultContainer = await CryptoVault.encryptVaultWithKey(state, vaultContainer, vaultKey);
      await SecureStorage.set("vault", vaultContainer);
      setSaveState("Сохранено");
    };
    clearTimeout(saveTimer);
    if (immediate) await save(); else saveTimer = setTimeout(() => save().catch((error) => showToast(error.message)), 350);
  }

  function cleanupDraft() {
    const coefficientIds = new Set(catalog.coefficients.map((x) => x.id));
    const holeServiceIds = new Set(catalog.services.filter((x) => x.is_per_hole).map((x) => x.id));
    const orderServiceIds = new Set(catalog.services.filter((x) => !x.is_per_hole).map((x) => x.id));
    const feeIds = new Set(catalog.fees.map((x) => x.id));
    draft.holes.forEach((hole) => {
      hole.coefficient_ids = (hole.coefficient_ids || []).filter((id) => coefficientIds.has(id));
      hole.services = Object.fromEntries(Object.entries(hole.services || {}).filter(([id]) => holeServiceIds.has(id)));
    });
    draft.order_services = Object.fromEntries(Object.entries(draft.order_services || {}).filter(([id]) => orderServiceIds.has(id)));
    draft.fee_ids = (draft.fee_ids || []).filter((id) => feeIds.has(id));
  }

  function scheduleAutoLock() {
    clearTimeout(lockTimer);
    if (!state) return;
    const minutes = Math.max(1, Number(state.preferences?.auto_lock_minutes || 5));
    lockTimer = setTimeout(lock, minutes * 60 * 1000);
  }

  function registerActivity() {
    if (!$("#app").hidden) scheduleAutoLock();
  }

  function lock() {
    clearTimeout(saveTimer);
    clearTimeout(lockTimer);
    vaultKey = null;
    state = null;
    catalog = null;
    draft = null;
    lastCalculation = null;
    $("#unlockCode").value = "";
    $("#unlockError").textContent = "";
    showOnly(vaultContainer ? "lockScreen" : "activationScreen");
  }

  function updateNetwork() {
    const online = navigator.onLine;
    $("#networkDot").classList.toggle("online", online);
    $("#networkText").textContent = online ? "Сеть доступна, расчёт всё равно локальный" : "Полностью офлайн";
  }

  function updateMinimumNote() {
    $("#minimumNote").textContent = draft.client_type === "юрлицо"
      ? "По максимальному диаметру"
      : `Мокрое ${money(catalog.rules.physical_minimum_wet)}; сухое ${money(catalog.rules.physical_minimum_dry)}`;
    $("#kmRateNote").textContent = `${money(catalog.rules.km_price_per_km)} / км`;
    $("#discount").max = String(catalog.rules.max_discount_percent);
    $("#discountNote").textContent = `Максимум ${catalog.rules.max_discount_percent}%`;
  }

  function choiceElement({ checked, title, meta, quantity, onChange }) {
    const wrapper = document.createElement("label");
    wrapper.className = `choice${checked ? " selected" : ""}`;
    const checkbox = document.createElement("input"); checkbox.type = "checkbox"; checkbox.checked = checked;
    const text = document.createElement("div");
    const titleEl = document.createElement("div"); titleEl.className = "choice-title"; titleEl.textContent = title;
    const metaEl = document.createElement("div"); metaEl.className = "choice-meta"; metaEl.textContent = meta;
    text.append(titleEl, metaEl); wrapper.append(checkbox, text);
    let qtyInput = null;
    if (quantity) {
      const qty = document.createElement("div"); qty.className = "qty-row";
      const minus = document.createElement("button"); minus.type = "button"; minus.textContent = "−";
      qtyInput = document.createElement("input"); qtyInput.type = "number"; qtyInput.inputMode = "decimal"; qtyInput.min = "0.1"; qtyInput.step = "0.1"; qtyInput.value = quantity.value ?? 1;
      const plus = document.createElement("button"); plus.type = "button"; plus.textContent = "+";
      qty.append(minus, qtyInput, plus); wrapper.append(qty);
      const adjust = (direction) => { const next = Math.max(.1, Number(qtyInput.value || 1) + direction * .1); qtyInput.value = String(Math.round(next * 10) / 10); onChange(checkbox.checked, Number(qtyInput.value)); };
      minus.addEventListener("click", (e) => { e.preventDefault(); adjust(-1); }); plus.addEventListener("click", (e) => { e.preventDefault(); adjust(1); });
      qtyInput.addEventListener("input", () => onChange(checkbox.checked, Number(qtyInput.value)));
    }
    checkbox.addEventListener("change", () => { wrapper.classList.toggle("selected", checkbox.checked); onChange(checkbox.checked, qtyInput ? Number(qtyInput.value) : undefined); });
    return wrapper;
  }

  function updateHoleSummary(card, hole) {
    $(".hole-summary", card).textContent = hole.diameter && hole.depth ? `${hole.diameter} мм × ${hole.depth} см · ${hole.material}` : "Заполните параметры";
  }

  function renderHole(hole, index) {
    const fragment = $("#holeTemplate").content.cloneNode(true); const card = $(".hole-card", fragment);
    card.dataset.id = hole.id; card.classList.toggle("expanded", index === draft.holes.length - 1 || draft.holes.length === 1);
    $(".hole-number", card).textContent = index + 1; updateHoleSummary(card, hole);
    const diameter = $(".diameter", card), depth = $(".depth", card), material = $(".material", card), drillingType = $(".drilling-type", card);
    diameter.value = hole.diameter; depth.value = hole.depth; material.value = hole.material; drillingType.value = hole.drilling_type;
    $(".hole-toggle", card).addEventListener("click", () => card.classList.toggle("expanded"));
    $(".remove-hole", card).addEventListener("click", () => { if (draft.holes.length === 1) return showToast("Нужно хотя бы одно отверстие"); draft.holes = draft.holes.filter((x) => x.id !== hole.id); lastCalculation = null; renderHoles(); persistState(); });
    const update = () => { hole.diameter = diameter.value; hole.depth = depth.value; hole.material = material.value; hole.drilling_type = drillingType.value; diameter.classList.toggle("invalid", Boolean(hole.diameter) && !DrillingLogic.findDiameterRange(catalog, Number(hole.diameter))); updateHoleSummary(card, hole); lastCalculation = null; updateExportState(); persistState(); };
    [diameter, depth, material, drillingType].forEach((el) => el.addEventListener("input", update));
    const coeffBox = $(".coefficients", card);
    catalog.coefficients.forEach((item) => coeffBox.append(choiceElement({ checked: hole.coefficient_ids.includes(item.id), title: item.name, meta: "Условие расчёта", onChange: (checked) => { hole.coefficient_ids = checked ? [...new Set([...hole.coefficient_ids, item.id])] : hole.coefficient_ids.filter((id) => id !== item.id); lastCalculation = null; updateExportState(); persistState(); } })));
    const servicesBox = $(".hole-services", card);
    catalog.services.filter((item) => item.is_per_hole).forEach((item) => servicesBox.append(choiceElement({ checked: Object.hasOwn(hole.services, item.id), title: item.name, meta: `за ${item.unit}`, quantity: { value: hole.services[item.id] ?? 1 }, onChange: (checked, qty) => { if (checked) hole.services[item.id] = qty || 1; else delete hole.services[item.id]; lastCalculation = null; updateExportState(); persistState(); } })));
    return fragment;
  }

  function renderHoles() { const box = $("#holesContainer"); box.replaceChildren(); draft.holes.forEach((hole, i) => box.append(renderHole(hole, i))); }

  function renderOrderChoices() {
    const services = $("#orderServicesContainer"); services.replaceChildren();
    catalog.services.filter((item) => !item.is_per_hole).forEach((item) => services.append(choiceElement({ checked: Object.hasOwn(draft.order_services, item.id), title: item.name, meta: `за ${item.unit}`, quantity: { value: draft.order_services[item.id] ?? 1 }, onChange: (checked, qty) => { if (checked) draft.order_services[item.id] = qty || 1; else delete draft.order_services[item.id]; lastCalculation = null; updateExportState(); persistState(); } })));
    const fees = $("#feesContainer"); fees.replaceChildren();
    catalog.fees.forEach((item) => fees.append(choiceElement({ checked: draft.fee_ids.includes(item.id), title: item.name, meta: "Фиксированная наценка", onChange: (checked) => { draft.fee_ids = checked ? [...new Set([...draft.fee_ids, item.id])] : draft.fee_ids.filter((id) => id !== item.id); lastCalculation = null; updateExportState(); persistState(); } })));
  }

  function renderCalculator() {
    renderHoles(); renderOrderChoices(); $("#km").value = draft.km; $("#clientType").value = draft.client_type; $("#discount").value = draft.discount; updateMinimumNote(); updateExportState();
  }

  function renderMetadata() {
    $("#clientLabel").textContent = state.client.name; $("#lockClientName").textContent = state.client.name;
    $("#metaClient").textContent = state.client.name; $("#metaVersion").textContent = state.package_version; $("#metaIssued").textContent = new Date(state.issued_at).toLocaleDateString("ru-RU");
  }

  function payloadFromDraft() { return { holes: draft.holes.map((h) => ({ diameter: h.diameter, depth: h.depth, material: h.material, drilling_type: h.drilling_type, coefficient_ids: [...h.coefficient_ids], services: { ...h.services } })), order_services: { ...draft.order_services }, fee_ids: [...draft.fee_ids], km: draft.km, client_type: draft.client_type, discount: draft.discount }; }
  function appendResult(label, value) { const row = document.createElement("div"); row.className = "result-row"; const a = document.createElement("span"), b = document.createElement("span"); a.textContent = label; b.textContent = money(value); row.append(a, b); $("#resultRows").append(row); }
  function renderResult(d) { $("#resultRows").replaceChildren(); appendResult("Стоимость работ", d.adjusted_holes_total); if (d.order_services_cost) appendResult("Общие услуги", d.order_services_cost); if (d.fees_cost) appendResult("Разовые наценки", d.fees_cost); if (d.km_cost) appendResult("Километраж", d.km_cost); if (d.discount_amount) appendResult("Скидка", -d.discount_amount); $("#resultTotal").textContent = money(d.total); $("#resultPanel").hidden = false; }
  function updateExportState() { $("#exportXlsxBtn").disabled = !lastCalculation; }

  function switchView(target) { $$(".view").forEach((v) => v.classList.toggle("active", v.id === `view-${target}`)); $$(".nav-btn").forEach((b) => b.classList.toggle("active", b.dataset.target === target)); window.scrollTo({ top: 0, behavior: "smooth" }); }

  async function downloadBlob(blob, filename, title) {
    const file = new File([blob], filename, { type: blob.type || "application/octet-stream" });
    if (navigator.canShare && navigator.canShare({ files: [file] })) { await navigator.share({ files: [file], title }); return; }
    const url = URL.createObjectURL(blob); const link = document.createElement("a"); link.href = url; link.download = filename; document.body.appendChild(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function activate(file, packagePassword, localCode) {
    const container = await readJsonFile(file); const payload = validatePackagePayload(await CryptoVault.openPackage(container, packagePassword));
    state = newStateFromPackage(payload); catalog = state.catalog; draft = emptyDraft(); state.draft = draft;
    vaultContainer = await CryptoVault.createVault(state, localCode); await SecureStorage.set("vault", vaultContainer);
    const opened = await CryptoVault.openVault(vaultContainer, localCode); vaultKey = opened.key;
    await SecureStorage.requestPersistence(); enterApp();
  }

  async function unlock(localCode) {
    if (Date.now() < blockedUntil) throw new Error(`Повторите через ${Math.ceil((blockedUntil - Date.now()) / 1000)} сек.`);
    try {
      const opened = await CryptoVault.openVault(vaultContainer, localCode); vaultKey = opened.key; state = opened.value; catalog = state.catalog; draft = state.draft || emptyDraft(); cleanupDraft(); unlockFailures = 0; enterApp();
    } catch (error) {
      unlockFailures += 1; if (unlockFailures >= 5) { blockedUntil = Date.now() + 30000; unlockFailures = 0; throw new Error("Слишком много попыток. Вход заблокирован на 30 секунд"); } throw error;
    }
  }

  function enterApp() { applyTheme(); renderCalculator(); renderMetadata(); updateNetwork(); showOnly("app"); scheduleAutoLock(); }

  function bindEvents() {
    $("#activationForm").addEventListener("submit", async (e) => { e.preventDefault(); const error = $("#activationError"); error.textContent = ""; const c1 = $("#activationLocalCode").value, c2 = $("#activationLocalCode2").value; if (c1 !== c2) return error.textContent = "Локальные коды не совпадают"; try { $("#activationForm button").disabled = true; await activate($("#activationFile").files?.[0], $("#activationPackagePassword").value, c1); e.target.reset(); showToast("Активация завершена"); } catch (x) { error.textContent = x.message; } finally { $("#activationForm button").disabled = false; } });
    $("#unlockForm").addEventListener("submit", async (e) => { e.preventDefault(); const error = $("#unlockError"); error.textContent = ""; try { $("#unlockButton").disabled = true; await unlock($("#unlockCode").value); } catch (x) { error.textContent = x.message; $("#unlockCode").select(); } finally { $("#unlockButton").disabled = false; } });
    $$(".nav-btn").forEach((b) => b.addEventListener("click", () => switchView(b.dataset.target)));
    $("#addHoleBtn").addEventListener("click", () => { draft.holes.push(emptyHole()); renderHoles(); lastCalculation = null; updateExportState(); persistState(); });
    $("#km").addEventListener("input", (e) => { draft.km = e.target.value; lastCalculation = null; updateExportState(); persistState(); });
    $("#discount").addEventListener("input", (e) => { draft.discount = e.target.value; lastCalculation = null; updateExportState(); persistState(); });
    $("#clientType").addEventListener("change", (e) => { draft.client_type = e.target.value; updateMinimumNote(); lastCalculation = null; updateExportState(); persistState(); });
    $("#calculateBtn").addEventListener("click", () => { try { const payload = payloadFromDraft(); const details = DrillingLogic.calculateOrder(catalog, payload); lastCalculation = { payload, details }; renderResult(details); updateExportState(); } catch (x) { alert(`Ошибка расчёта:\n${x.message}`); } });
    $("#exportXlsxBtn").addEventListener("click", async () => { if (!lastCalculation) return; try { await XlsxExport.saveWorkbook(lastCalculation.payload, lastCalculation.details); } catch (x) { alert(`Не удалось сохранить Excel:\n${x.message}`); } });
    $("#themeBtn").addEventListener("click", async () => { state.preferences.theme = document.body.classList.contains("dark") ? "light" : "dark"; localStorage.setItem("drill-theme", state.preferences.theme); applyTheme(); await persistState(true); });
    $("#lockBtn").addEventListener("click", async () => { await persistState(true); lock(); });
    $("#updatePackageForm").addEventListener("submit", async (e) => { e.preventDefault(); try { const container = await readJsonFile($("#updatePackageFile").files?.[0]); const payload = validatePackagePayload(await CryptoVault.openPackage(container, $("#updatePackagePassword").value)); if (payload.client.id !== state.client.id && !confirm("Файл относится к другому клиенту. Заменить текущую конфигурацию?")) return; state.client = payload.client; state.package_version = payload.package_version; state.issued_at = payload.issued_at; state.expires_at = payload.expires_at || null; state.options = payload.options || {}; state.catalog = clone(payload.catalog); catalog = state.catalog; cleanupDraft(); lastCalculation = null; await persistState(true); renderCalculator(); renderMetadata(); e.target.reset(); showToast("Прайс обновлён"); } catch (x) { alert(`Не удалось импортировать:\n${x.message}`); } });
    $("#exportVaultBtn").addEventListener("click", async () => { await persistState(true); const blob = new Blob([CryptoVault.serialize(vaultContainer)], { type: "application/json" }); await downloadBlob(blob, `drilling_secure_backup_${new Date().toISOString().slice(0,10)}.drillvault`, "Зашифрованная копия"); });
    $("#restoreVaultInput").addEventListener("change", async (e) => { const file = e.target.files?.[0]; if (!file) return; try { const candidate = await readJsonFile(file); if (candidate.format !== CryptoVault.VAULT_FORMAT) throw new Error("Это не зашифрованная копия калькулятора"); if (!confirm("Заменить текущие данные зашифрованной копией?")) return; await SecureStorage.set("vault", candidate); vaultContainer = candidate; showToast("Копия загружена. Введите её код доступа"); lock(); } catch (x) { alert(x.message); } finally { e.target.value = ""; } });
    $("#changeCodeForm").addEventListener("submit", async (e) => { e.preventDefault(); const current = $("#currentCode").value, next = $("#newCode").value; if (next !== $("#newCode2").value) return alert("Новые коды не совпадают"); try { await CryptoVault.openVault(vaultContainer, current); vaultContainer = await CryptoVault.createVault(state, next); await SecureStorage.set("vault", vaultContainer); const opened = await CryptoVault.openVault(vaultContainer, next); vaultKey = opened.key; e.target.reset(); showToast("Код изменён"); } catch (x) { alert(x.message); } });
    $("#offlineCheckBtn").addEventListener("click", async () => { const lines = []; lines.push(`Service Worker: ${navigator.serviceWorker?.controller ? "активен" : "ещё не активен — закройте и откройте приложение"}`); const persistence = await SecureStorage.requestPersistence(); lines.push(`Локальное хранилище: ${persistence.persisted ? "постоянное" : "обычное, нужна резервная копия"}`); lines.push(`Сеть сейчас: ${navigator.onLine ? "есть" : "нет"}`); $("#offlineCheckResult").textContent = lines.join(" · "); });
    $("#resetBtn").addEventListener("click", async () => { if (!confirm("Удалить прайс, настройки и черновик с этого iPhone?")) return; await SecureStorage.remove("vault"); vaultContainer = null; lock(); });
    window.addEventListener("online", updateNetwork); window.addEventListener("offline", updateNetwork);
    ["pointerdown", "keydown", "touchstart"].forEach((name) => document.addEventListener(name, registerActivity, { passive: true }));
    document.addEventListener("visibilitychange", () => { clearTimeout(hiddenTimer); if (document.hidden && !$("#app").hidden) hiddenTimer = setTimeout(lock, 60000); else if (!document.hidden) scheduleAutoLock(); });
  }

  async function initialize() {
    bindEvents(); applyTheme();
    vaultContainer = await SecureStorage.get("vault");
    if ("serviceWorker" in navigator && location.protocol === "https:") {
      try { await navigator.serviceWorker.register("./sw.js", { scope: "./" }); } catch (error) { console.warn("Service Worker", error); }
    }
    await SecureStorage.requestPersistence();
    showOnly(vaultContainer ? "lockScreen" : "activationScreen");
  }

  initialize().catch((error) => { document.body.innerHTML = `<main style="padding:24px;font-family:sans-serif"><h1>Ошибка запуска</h1><p>${String(error.message || error)}</p></main>`; });
})();
