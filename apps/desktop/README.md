# LLLanyard desktop (Tauri)

A thin native window around the local LLLanyard UI. It starts `lllanyard ui --no-open --print-url`, checks that the printed
address is `http://127.0.0.1:<port>/#s=<secret>`, and shows it. The page gets **no Tauri APIs** (empty capability list); all
work happens in the CLI/core that you can audit. The server is stopped when the window closes.

```
npm link -w packages/cli               # from the repo root: the app launches the `lllanyard` command
cd apps/desktop && npm install
npm run dev                            # or: npx tauri build --bundles app
```

Needs Rust (`brew install rustup && rustup default stable`) and the Xcode command line tools. The icons in
`src-tauri/icons` are generated from `icon-source.png` with `npx tauri icon icon-source.png`.

The app finds `lllanyard` and `node` in `/opt/homebrew/bin` and `/usr/local/bin` as well as the PATH it was given, because
apps opened from Finder get a minimal PATH.

Builds and runs on macOS (Apple Silicon, Tauri 2.12). Launched from Finder it starts the UI server, shows the UI, and
stops the server on quit. It needs Node and the `lllanyard` command installed, and it isn't signed, so the first launch
needs right-click > Open. There are no Windows or Linux builds.
