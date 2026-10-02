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
  let literalBase;
  const literal = pointer => {
    const cached = literals.get(pointer);
    if (cached !== undefined) return cached;
    const data = bytes();
    let end = pointer;
    while (data[end] !== 0) end++;
    const value = text(pointer, end - pointer);
    literals.set(pointer, value);
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
  const argument = data => {
    data >>>= 0;
    if (data === 0xffffffff) return true;
    if (data === 0xfffffffe) return false;
    if (!(data & 0x80000000)) return values[data];
    return data <= 0xffffefff ? 0xffffefff - data : literal(literalBase + 0xfffffffd - data);
  };
  const args = (pointer, length) => {
    const fields = new Uint32Array(wasm.memory.buffer, pointer, length);
    return Array.from({ length }, (_, index) => argument(fields[index]));
  };
  const dom = {
    // retain
    a: index => { pinned.add(index); return index; },
    // string
    c: (pointer, length) => hold(text(pointer, length)),
    // object
    d: () => hold({}),
    // make_number
    e: value => hold(value),
    // array
    f: (pointer, length) => hold(args(pointer, length)),
    // get
    g: (index, key) => hold(values[index][names[key + 64]]),
    // get_number
    h: (index, key) => Number(values[index][names[key + 64]]),
    // get_boolean
    i: (index, key) => Boolean(values[index][names[key + 64]]),
    // try_get
    j: (index, key) => caught(() => values[index][names[key + 64]]),
    // set
    k: (index, key, data) => {
      values[index][names[key + 64]] = argument(data);
    },
    // call
    l: (index, key, argumentsPointer, argumentsLength) => hold(
      values[index][names[key + 64]](...args(argumentsPointer, argumentsLength))
    ),
    // call0
    m: (index, key) => hold(values[index][names[key + 64]]()),
    // call1
    n: (index, key, data) => hold(values[index][names[key + 64]](argument(data))),
    // call2
    o: (index, key, data, data2) => hold(values[index][names[key + 64]](argument(data), argument(data2))),
    // try_call
    p: (index, key, argumentsPointer, argumentsLength) => caught(() =>
      values[index][names[key + 64]](...args(argumentsPointer, argumentsLength))
    ),
    // construct
    q: (key, argumentsPointer, argumentsLength) => caught(() =>
      Reflect.construct(globalThis[names[key + 64]], args(argumentsPointer, argumentsLength))
    ),
    // truthy
    r: index => Boolean(values[index]),
    // equal
    s: (a, b) => values[a] === values[b],
    // equal_text
    t: (index, data) => values[index] === argument(data),
    // numeric
    u: index => Number(values[index]),
    // instance
    v: (index, key) => values[index] instanceof globalThis[names[key + 64]],
    // string_length
    w: index => { encoded = encoder.encode(values[index]); return encoded.length; },
    // string_copy
    x: pointer => bytes().set(encoded, pointer),
    // bytes_length
    y: index => values[index].byteLength,
    // bytes_copy
    z: (index, pointer) => bytes().set(new Uint8Array(values[index]), pointer),
    // listen
    A: (index, pointer, length) => {
      const end = pointer + length, data = bytes();
      while (pointer < end) {
        const descriptor = data[pointer++], kind = descriptor & 127, start = pointer;
        while (pointer < end && data[pointer] !== 0) pointer++;
        const name = text(start, pointer - start);
        pointer++;
        values[index].addEventListener(name, event => run(() => wasm.dispatch(kind, hold(event))), Boolean(descriptor & 128));
      }
    },
    // promise
    B: (index, kind, token) => {
      values[index].then(
        value => run(() => wasm.resolved(kind, token, hold(value))),
        () => run(() => wasm.rejected(kind, token))
      );
    },
    // timeout
    C: (milliseconds, kind, token) => setTimeout(() => run(() => wasm.timer(kind, token)), milliseconds),
    // frame
    D: (kind, token) => requestAnimationFrame(() => run(() => wasm.timer(kind, token))),
    // try_call0
    E: (index, key) => caught(() => values[index][names[key + 64]]()),
    // try_call1
    F: (index, key, data) => caught(() => values[index][names[key + 64]](argument(data))),
    // try_call2
    G: (index, key, data, data2) => caught(() => values[index][names[key + 64]](argument(data), argument(data2))),
    // construct0
    H: key => caught(() => new globalThis[names[key + 64]]()),
    // construct1
    I: (key, data) => caught(() => new globalThis[names[key + 64]](argument(data))),
    // construct2
    J: (key, data, data2) => caught(() => new globalThis[names[key + 64]](argument(data), argument(data2))),
    // array2
    K: (data, data2) => hold([argument(data), argument(data2)]),
    // array3
    L: (data, data2, data3) => hold([argument(data), argument(data2), argument(data3)]),
    // call3
    M: (index, key, data, data2, data3) => hold(values[index][names[key + 64]](argument(data), argument(data2), argument(data3))),
    // get_index
    N: (index, position) => hold(values[index][position]),
    // call1_boolean
    O: (index, key, data) => Boolean(values[index][names[key + 64]](argument(data))),
    // replace_retained
    P: (old, index) => {
      pinned.add(index);
      if (old > 2 && old !== index) { pinned.delete(old); release(old); }
      return index;
    },
    // call1_void
    Q: (index, key, data) => { values[index][names[key + 64]](argument(data)); },
    // get_integer
    U: (index, key) => values[index][names[key + 64]] >>> 0,
    // from_literal
    T: data => hold(argument(data)),
    // literal_pool
    S: pointer => { literalBase = pointer; },
    // get2
    R: (index, key, next) => hold(values[index][names[key + 64]][names[next + 64]])
  };
  ({ instance: { exports: wasm } } = await WebAssembly.instantiateStreaming(fetch(url, { integrity }), { d: dom }));
  run(() => wasm.start());
  dispatchEvent(new CustomEvent("TrunkApplicationStarted", { detail: { wasm } }));
}
