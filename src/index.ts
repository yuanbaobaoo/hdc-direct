/**
 * hdc-direct 库入口：协议编码、认证、会话、target 管理。
 *
 * 作为库被其他 Node 工具引用时：
 * ```ts
 * import { HdcSession } from 'hdc-direct';
 * const s = await HdcSession.connect('127.0.0.1', 46273);
 * console.log(await s.shellStr('id'));
 * s.close();
 * ```
 */
export * from './proto.js';
export * from './auth.js';
export * from './session.js';
export * from './targets.js';
export { run, VERSION_OUT } from './cli.js';
