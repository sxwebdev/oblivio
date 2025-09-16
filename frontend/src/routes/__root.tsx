import { Outlet, createRootRoute } from "@tanstack/react-router";
import { TanStackRouterDevtoolsPanel } from "@tanstack/react-router-devtools";
import { TanStackDevtools } from "@tanstack/react-devtools";

import Header from "../components/Header";
import { Toaster } from "@/components/ui/sonner";

export const Route = createRootRoute({
  component: () => (
    <>
      <div className="mx-auto max-w-screen-lg px-4">
        <Header />
        <Outlet />
      </div>
      <Toaster position="bottom-right" />
      <TanStackDevtools
        config={{ position: "bottom-left" }}
        plugins={[
          { name: "Tanstack Router", render: <TanStackRouterDevtoolsPanel /> },
        ]}
      />
    </>
  ),
});
