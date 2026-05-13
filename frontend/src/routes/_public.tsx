import { Outlet, createFileRoute } from "@tanstack/react-router"

// _public is the pathless layout for anonymous routes (login, register, recover).
// Sign-in state intentionally does not redirect away from these pages so the
// user can sign out elsewhere and land here.
export const Route = createFileRoute("/_public")({
  component: PublicLayout,
})

function PublicLayout() {
  return (
    <div className="flex min-h-svh items-center justify-center p-6">
      <div className="w-full max-w-md">
        <Outlet />
      </div>
    </div>
  )
}
