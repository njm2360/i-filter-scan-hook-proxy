# i-FILTER ファイル検査フックProxy

上流サーバーが`Transfer-Encoding: chunked`で返す場合、i-FILTERはAcceptヘッダーを無視して検査中ページのHTMLを返す。
（`Content-Length`ありの場合は実データを低速トリクル返却するため問題なし）※技術的には可能なのでi-FILTERが実装してないだけ。
ブラウザの場合は`Content-Disposition: attachment`でHTMLがダウンロードされ、手動で開くことでスキャン完了後にファイルを取得できるが、
CLIツールの場合はZIPのはずがHTMLが返却されることでツールが動作しなくなるのでその対策スクリプトです。

## 使用方法

`.env`を作成して上流Proxyサーバーを設定してください。
認証が必要な場合はあらかじめローカルでCntlm等を動かしてそちらに向けてください。

`uv run main.py`

`certs`フォルダにSSLインスペクション用証明書ができるのであらかじめシステムCAに組み込みます

```sh
sudo cp ./certs/mitmproxy-ca-cert.pem \
    /usr/local/share/ca-certificates/mitmproxy-ca.crt
sudo update-ca-certificates
```

必要に応じてCLIツール側のProxy設定をこのProxyに向けてください。
スループットが落ちるのでシステム全体をこのプロキシに向けるのは非推奨です。

なおこの実装ではトリクル返却が効かず、レスポンスをブロックするためツールによっては
ダウンロードに失敗する場合があります。その場合は何度か試すと成功することがあります。
（i-FILTERはスキャンしたファイルをキャッシュし、スキャン後は即時返すため）
