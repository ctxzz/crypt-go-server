# Go-server
## パッケージ
* crypto
  - 鍵，暗号化メソッド
* public
  - HTML
* sample
  - RSA暗号，Hybrid暗号のsample
* videos
  - Videoファイル

## How to Use
* 公開鍵，暗号鍵の生成
  - URL:localhost:8080/generateRSAKey
  - 2048ビットのRSAキーペアを生成．
  - privateKey.pem，publicKey.pemで出力
* 映像ファイルの暗号化
  - URL:localhost:8080/encrypt/hybrid/[VIDEONAME]
  - videosディレクトリにある映像ファイルを指定
  - 映像ファイル名 + .txtで出力
* 映像ファイルの復号・ストリーミング再生
  - URL:localhost:8080/streaming/hybrid/[VIDEONAME].txt
