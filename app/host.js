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
    if (kind === 0xfffffffe) return data >>> 0;
    const length = (kind >>> 1) - 1;
    return kind & 1 ? literal(data, length) : text(data, length);
  };
  const args = (pointer, length) => {
    const fields = new Uint32Array(wasm.memory.buffer, pointer, length * 2);
    return Array.from({ length }, (_, index) => argument(fields[index * 2], fields[index * 2 + 1]));
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
    k: (index, key, data, kind) => {
      values[index][names[key + 64]] = argument(data, kind);
    },
    // call
    l: (index, key, argumentsPointer, argumentsLength) => hold(
      values[index][names[key + 64]](...args(argumentsPointer, argumentsLength))
    ),
    // call0
    m: (index, key) => hold(values[index][names[key + 64]]()),
    // call1
    n: (index, key, data, kind) => hold(values[index][names[key + 64]](argument(data, kind))),
    // call2
    o: (index, key, data, kind, data2, kind2) => hold(values[index][names[key + 64]](argument(data, kind), argument(data2, kind2))),
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
    t: (index, pointer, length) => values[index] === literal(pointer, length),
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
        const kind = data[pointer++], start = pointer;
        while (pointer < end && data[pointer] !== 0) pointer++;
        const name = text(start, pointer - start);
        pointer++;
        values[index].addEventListener(name, event => run(() => wasm.dispatch(kind, hold(event))));
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
    F: (index, key, data, kind) => caught(() => values[index][names[key + 64]](argument(data, kind))),
    // try_call2
    G: (index, key, data, kind, data2, kind2) => caught(() => values[index][names[key + 64]](argument(data, kind), argument(data2, kind2))),
    // construct0
    H: key => caught(() => new globalThis[names[key + 64]]()),
    // construct1
    I: (key, data, kind) => caught(() => new globalThis[names[key + 64]](argument(data, kind))),
    // construct2
    J: (key, data, kind, data2, kind2) => caught(() => new globalThis[names[key + 64]](argument(data, kind), argument(data2, kind2))),
    // array2
    K: (data, kind, data2, kind2) => hold([argument(data, kind), argument(data2, kind2)]),
    // array3
    L: (data, kind, data2, kind2, data3, kind3) => hold([argument(data, kind), argument(data2, kind2), argument(data3, kind3)]),
    // call3
    M: (index, key, data, kind, data2, kind2, data3, kind3) => hold(values[index][names[key + 64]](argument(data, kind), argument(data2, kind2), argument(data3, kind3))),
    // get_index
    N: (index, position) => hold(values[index][position]),
    // call1_boolean
    O: (index, key, data, kind) => Boolean(values[index][names[key + 64]](argument(data, kind))),
    // replace_retained
    P: (old, index) => {
      pinned.add(index);
      if (old > 2 && old !== index) { pinned.delete(old); release(old); }
      return index;
    },
    // call1_void
    Q: (index, key, data, kind) => { values[index][names[key + 64]](argument(data, kind)); },
    // get2
    R: (index, key, next) => hold(values[index][names[key + 64]][names[next + 64]])
  };
  ({ instance: { exports: wasm } } = await WebAssembly.instantiateStreaming(fetch(url, { integrity }), { d: dom }));
  run(() => wasm.start());
  dispatchEvent(new CustomEvent("TrunkApplicationStarted", { detail: { wasm } }));
}
