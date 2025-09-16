import { defineConfig } from "vite";
import path from "path";
import viteReact from "@vitejs/plugin-react-swc";
import { tanstackRouter } from "@tanstack/router-plugin/vite";
import tailwindcss from "@tailwindcss/vite";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    tanstackRouter({
      target: "react",
      autoCodeSplitting: true,
    }),
    viteReact(),
    tailwindcss(),
  ],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
      "state": path.resolve(__dirname, "./src/state"),
      "pages": path.resolve(__dirname, "./src/pages"),
      "components": path.resolve(__dirname, "./src/components"),
      "lib": path.resolve(__dirname, "./src/lib"),
      "hooks": path.resolve(__dirname, "./src/hooks"),
    },
  },
});
