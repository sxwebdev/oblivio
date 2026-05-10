package repo_entries

import "github.com/sxwebdev/oblivio/internal/models"

// NullEntryKind aliases the central nullable-enum wrapper so the sqlc-generated
// code in this package can compile without re-declaring it.
type NullEntryKind = models.NullEntryKind
