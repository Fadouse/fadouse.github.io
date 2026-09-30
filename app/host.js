// Browser API bindings. Application state and behavior live in WASM.
export default async function initialize(url, integrity) {
  const names = __BROWSER_KEYS__;
  const values = [null, window, document];
  const available = [];
  const pinned = new Set([0, 1, 2]);
  const frames = [];
  const release = index => {
    if (values[index] !== undefined) { values[index] = undefined; available.push(index); }
  };
  const run = action => {
    frames.push([]);
    try { return action(); }
    finally { for (const index of frames.pop()) if (!pinned.has(index)) release(index); }
  };
  let wasm;
  let encoded;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", { ignoreBOM: true });
  let memoryBytes;
  const bytes = () => {
    if (memoryBytes?.buffer !== wasm.memory.buffer) memoryBytes = new Uint8Array(wasm.memory.buffer);
    return memoryBytes;
  };
  const text = (pointer, length) => decoder.decode(bytes().subarray(pointer, pointer + length));
  const literals = new Map();
  const literal = (pointer, length) => {
    const cached = literals.get(pointer);
    if (cached?.[0] === length) return cached[1];
    const value = text(pointer, length);
    literals.set(pointer, [length, value]);
    return value;
  };
  const hold = value => {
    if (value == null) return 0;
    const index = available.pop() ?? values.length;
    values[index] = value;
    frames[frames.length - 1].push(index);
    return index;
  };
  const caught = action => {
    try { return hold(action()); }
    catch (error) { return -hold(error); }
  };
  const argument = (data, kind) => {
    kind >>>= 0;
    if (kind === 0) return values[data];
    if (kind === 0xffffffff) return Boolean(data);
    const length = (kind >>> 1) - 1;
    return kind & 1 ? literal(data, length) : text(data, length);
  };
  const args = (pointer, length) => {
    const fields = new Uint32Array(wasm.memory.buffer, pointer, length * 2);
    return Array.from({ length }, (_, index) => argument(fields[index * 2], fields[index * 2 + 1]));
  };
  const dom = {
    retain: index => { pinned.add(index); return index; },
    release: index => { pinned.delete(index); release(index); },
    string: (pointer, length) => hold(text(pointer, length)),
    object: () => hold({}),
    make_number: value => hold(value),
    array: (pointer, length) => hold(args(pointer, length)),
    get: (index, key) => hold(values[index][names[key]]),
    try_get: (index, key) => caught(() => values[index][names[key]]),
    set: (index, key, data, kind) => {
      values[index][names[key]] = argument(data, kind);
    },
    call: (index, key, argumentsPointer, argumentsLength) => hold(
      values[index][names[key]](...args(argumentsPointer, argumentsLength))
    ),
    call0: (index, key) => hold(values[index][names[key]]()),
    call1: (index, key, data, kind) => hold(values[index][names[key]](argument(data, kind))),
    call2: (index, key, data, kind, data2, kind2) => hold(values[index][names[key]](argument(data, kind), argument(data2, kind2))),
    try_call: (index, key, argumentsPointer, argumentsLength) => caught(() =>
      values[index][names[key]](...args(argumentsPointer, argumentsLength))
    ),
    construct: (key, argumentsPointer, argumentsLength) => caught(() =>
      Reflect.construct(globalThis[names[key]], args(argumentsPointer, argumentsLength))
    ),
    truthy: index => Boolean(values[index]),
    equal: (a, b) => values[a] === values[b],
    equal_text: (index, pointer, length) => values[index] === text(pointer, length),
    numeric: index => Number(values[index]),
    instance: (index, key) => values[index] instanceof globalThis[names[key]],
    string_length: index => { encoded = encoder.encode(values[index]); return encoded.length; },
    string_copy: pointer => bytes().set(encoded, pointer),
    bytes_length: index => values[index].byteLength,
    bytes_copy: (index, pointer) => bytes().set(new Uint8Array(values[index]), pointer),
    listen: (index, pointer, length, kind) => {
      values[index].addEventListener(text(pointer, length), event => run(() => wasm.dispatch(kind, hold(event))));
    },
    promise: (index, kind, token) => {
      values[index].then(
        value => run(() => wasm.resolved(kind, token, hold(value))),
        () => run(() => wasm.rejected(kind, token))
      );
    },
    timeout: (milliseconds, kind, token) => setTimeout(() => run(() => wasm.timer(kind, token)), milliseconds)
  };
  ({ instance: { exports: wasm } } = await WebAssembly.instantiateStreaming(fetch(url, { integrity }), { dom }));
  run(() => wasm.start());
  dispatchEvent(new CustomEvent("TrunkApplicationStarted", { detail: { wasm } }));
}
