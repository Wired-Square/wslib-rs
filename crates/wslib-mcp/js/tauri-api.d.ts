// Only for typechecking this directory; a consumer's copy uses the real package.
declare module "@tauri-apps/api/event" {
  export type UnlistenFn = () => void;
  export interface Event<T> {
    event: string;
    id: number;
    payload: T;
  }
  export function listen<T>(event: string, handler: (event: Event<T>) => void): Promise<UnlistenFn>;
  export function emit(event: string, payload?: unknown): Promise<void>;
}
