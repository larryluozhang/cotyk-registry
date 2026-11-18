import argparse

import uvicorn

import registry.config as cfg


def main():
    parser = argparse.ArgumentParser(description="COTYK Bridge Registry")
    parser.add_argument("--host", default=cfg.env("REGISTRY_HOST", cfg.DEFAULT_HOST))
    parser.add_argument("--port", type=int,
                        default=int(cfg.env("REGISTRY_PORT", str(cfg.DEFAULT_PORT))))
    parser.add_argument("--db", default=cfg.env("REGISTRY_DB_PATH", cfg.DEFAULT_DB_PATH))
    args = parser.parse_args()

    from registry.app import create_app
    uvicorn.run(create_app(args.db), host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
