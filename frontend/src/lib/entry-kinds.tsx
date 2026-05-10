// Maps EntryKind enum values to display metadata. Used by list/detail
// views and the create form.

import {
  CreditCard,
  FileText,
  IdCard,
  KeyRound,
  ShieldCheck,
  TerminalSquare,
  type LucideIcon,
} from "lucide-react"

import { EntryKind } from "@/api/gen/oblivio/v1/entries_pb"

export type EntryKindMeta = {
  kind: EntryKind
  label: string
  Icon: LucideIcon
  color: string
}

export const ENTRY_KINDS: EntryKindMeta[] = [
  {
    kind: EntryKind.LOGIN,
    label: "Login",
    Icon: KeyRound,
    color: "text-sky-500",
  },
  {
    kind: EntryKind.TOTP,
    label: "Authenticator",
    Icon: ShieldCheck,
    color: "text-emerald-500",
  },
  {
    kind: EntryKind.CARD,
    label: "Card",
    Icon: CreditCard,
    color: "text-purple-500",
  },
  {
    kind: EntryKind.IDENTITY,
    label: "Identity",
    Icon: IdCard,
    color: "text-pink-500",
  },
  {
    kind: EntryKind.SSH_KEY,
    label: "SSH key",
    Icon: TerminalSquare,
    color: "text-amber-500",
  },
  {
    kind: EntryKind.NOTE,
    label: "Note",
    Icon: FileText,
    color: "text-slate-500",
  },
]

export function entryKindMeta(kind: EntryKind): EntryKindMeta {
  return (
    ENTRY_KINDS.find((m) => m.kind === kind) ?? {
      kind: EntryKind.UNSPECIFIED,
      label: "Item",
      Icon: KeyRound,
      color: "text-muted-foreground",
    }
  )
}
