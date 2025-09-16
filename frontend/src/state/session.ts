// In-memory session state only
import { Store } from "@tanstack/store";

export type SessionState = {
  isAuthed: boolean;
};

export const sessionStore = new Store<SessionState>({ isAuthed: false });

export function logout() {
  sessionStore.setState({ isAuthed: false });
}
