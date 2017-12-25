var renderer = PIXI.autoDetectRenderer(800, 600, { backgroundColor: 0x1099bb });
document.body.appendChild(renderer.view);
var stage = new PIXI.Container();
var texture = PIXI.Texture.fromVideoUrl('http://localhost:8080/videos/k0104.mp4');
var videoSprite = new PIXI.Sprite(texture);
videoSprite.width = 400;
videoSprite.height = 300;
videoSprite.x = 400;
videoSprite.y = 300;
stage.addChild(videoSprite);
function animate() {
    requestAnimationFrame(animate);
    videoSprite.rotation += 0.01;
    renderer.render(stage);
}
animate();
