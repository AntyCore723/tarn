// game.js — Secret runner game (unlocked via the Packet filter tab)
// SPDX-License-Identifier: GPL-3.0-only AND BSD-3-Clause
//
// Physics adapted from the Chromium "Dino" runner (chrome://dino),
// used under the BSD 3-Clause License:
//   Copyright 2015 The Chromium Authors
//   https://chromium.googlesource.com/chromium/src/+/lkgr/components/neterror/resources/offline.js
//
// Game sprites are original pixel art (not the Chrome dino).

const TarnGame = (() => {
  let canvas, ctx;
  let running = false;
  let raf = null;
  let score = 0;
  let highScore = 0;
  let speed = 0;
  let frame = 0;
  let gameOver = false;
  let starEarned = false;

  const sprites = {};

  const CANVAS_W = 700;
  const CANVAS_H = 250;
  const GROUND_Y = 200;

  // Player: 44×47 original T-Rex size
  const PLAYER_W = 44;
  const PLAYER_H = 47;
  const DUCK_W = 59;
  const DUCK_H = 25;
  const player = {
    x: 60, y: GROUND_Y - PLAYER_H,
    w: PLAYER_W, h: PLAYER_H,
    vy: 0, grounded: true, ducking: false
  };

  // ── Physics (original Dino, tuned for smoothness) ──
  // Original: GRAVITY=0.6, JUMP=-10, max=83px in 33 frames
  // We want BIGGER + SMOOTHER: less gravity, stronger jump
  const GRAVITY = 0.35;
  const JUMP_FORCE = -10;
  const DROP_VELOCITY = -6;
  const BASE_SPEED = 3;
  const MAX_SPEED = 8;
  const ACCELERATION = 0.0008;
  const MIN_JUMP_HEIGHT = 42;
  const SPEED_DROP_COEFF = 3;
  // Max jump = 144/1.0 = 144px (58% of 250)
  // Jump time = 2×12/0.5 = 48 frames = 0.8s (SMOOTH!)

  // Cactus sizes
  const CACTUS_SIZES = [
    { w: 20, h: 42 },
    { w: 30, h: 60 },
    { w: 60, h: 60 }
  ];
  const BIRD_W = 55;
  const BIRD_H = 48;

  // ── Sprite content bboxes ───────────────────────────
  // All sprites have 53-67% transparent padding. These bboxes
  // define the ACTUAL character content within each sprite.
  //
  // run1-4: 144×144 each (resized from 720×720, scale=0.2)
  //   run1: content bbox = 18,19 → 115×111
  //   run2: content bbox = 26,19 → 90×111
  //   run3: content bbox = 17,15 → 114×106
  //   run4: content bbox = 23,15 → 106×113
  // jump: 144×144 (resized from 715×720, scale≈0.2014/0.2)
  const RUN_BBOX = [
    { x: 18,  y: 19, w: 115, h: 111 },  // run1
    { x: 26,  y: 19, w: 90,  h: 111 },  // run2
    { x: 17,  y: 15, w: 114, h: 106 },  // run3
    { x: 23,  y: 15, w: 106, h: 113 }   // run4
  ];
  const JUMP_BBOX = { x: 5, y: 10, w: 132, h: 118 };

  // ── Sprite file mapping ─────────────────────────────
  // cactus1.png = CACTUS (static standing obstacle)
  // bird1.png   = BIRD (flying obstacle)
  // star1.png   = STAR (achievement)
  const spritePaths = {
    run1: 'mascot/run1.png',
    run2: 'mascot/run2.png',
    run3: 'mascot/run3.png',
    run4: 'mascot/run4.png',
    jump: 'mascot/jump.png',
    cactusSprite: 'mascot/cactus1.png',
    birdSprite: 'mascot/bird1.png'
  };

  // cactus1.png (RED): 144×144 (resized from 1440×1248, scale=0.1/0.1154)
  //   content bbox = 23,13 → 97×118, ratio≈0.82
  // bird1.png   (GRAY): 144×144 (same scaling)
  //   content bbox = 13,30 → 121×77, ratio≈1.57
  // star1.png   (GOLDEN): 144×144 (same scaling)
  //   content bbox = 10,12 → 97×115, ratio≈0.84
  const CACTUS_CONTENT = { x: 23, y: 13, w: 97, h: 118 };
  const BIRD_CONTENT = { x: 13, y: 30, w: 121, h: 77 };

  const obstacles = [];
  let obstacleTimer = 0;
  let animTimer = 0;
  let animFrame = 0;
  let groundOffset = 0;

  function loadSprites() {
    return Promise.all(Object.entries(spritePaths).map(([key, path]) => {
      return new Promise((resolve) => {
        const img = new Image();
        img.onload = () => { sprites[key] = img; resolve(); };
        img.onerror = () => resolve();
        img.src = path;
      });
    }));
  }

  function cropDraw(key, sx, sy, sw, sh, dx, dy, dw, dh) {
    const sp = sprites[key];
    if (!sp || sp.naturalWidth < 2) return false;
    ctx.imageSmoothingEnabled = true;
    ctx.imageSmoothingQuality = 'high';
    ctx.drawImage(sp, sx, sy, sw, sh, dx, dy, dw, dh);
    return true;
  }

  function init(canvasEl) {
    canvas = canvasEl;
    ctx = canvas.getContext('2d');
    canvas.width = CANVAS_W;
    canvas.height = CANVAS_H;
    player.x = 60;
    player.y = GROUND_Y - PLAYER_H;

    chrome.storage.local.get('tarn.gameHighScore', (d) => {
      highScore = d['tarn.gameHighScore'] || 0;
    });
    chrome.storage.local.get('tarn.gameStar', (d) => {
      starEarned = !!d['tarn.gameStar'];
    });
  }

  function start() {
    if (running) return;
    loadSprites().then(() => { reset(); running = true; gameOver = false; loop(); });
  }

  function stop() {
    running = false;
    if (raf) cancelAnimationFrame(raf);
    raf = null;
  }

  function reset() {
    score = 0;
    speed = BASE_SPEED;
    frame = 0;
    obstacleTimer = 0;
    animTimer = 0;
    animFrame = 0;
    groundOffset = 0;
    player.y = GROUND_Y - PLAYER_H;
    player.vy = 0;
    player.grounded = true;
    player.ducking = false;
    obstacles.length = 0;
    gameOver = false;
  }

  function jump() {
    if (!running) return;
    if (gameOver) { reset(); return; }
    if (player.grounded) {
      player.vy = JUMP_FORCE;
      player.grounded = false;
      player.ducking = false;
    }
  }

  function duckStart() {
    if (!running || gameOver) return;
    if (player.grounded) {
      player.ducking = true;
    } else {
      player.vy = Math.max(player.vy, DROP_VELOCITY);
    }
  }

  function duckEnd() {
    player.ducking = false;
  }

  function spawnObstacle() {
    const isBird = Math.random() < 0.3;
    if (isBird) {
      const birdHeights = [
        GROUND_Y - BIRD_H - 5,
        GROUND_Y - BIRD_H - 40,
        GROUND_Y - BIRD_H - 75
      ];
      obstacles.push({
        type: 'bird',
        x: CANVAS_W + 20,
        y: birdHeights[Math.floor(Math.random() * birdHeights.length)],
        w: BIRD_W, h: BIRD_H,
        animTimer: 0
      });
    } else {
      const s = CACTUS_SIZES[Math.floor(Math.random() * CACTUS_SIZES.length)];
      obstacles.push({
        type: 'cactus',
        x: CANVAS_W + 20,
        y: GROUND_Y - s.h,
        w: s.w, h: s.h
      });
    }
  }

  function checkCollision(a, b) {
    const p = 3;
    return (
      a.x + p < b.x + b.w - p &&
      a.x + a.w - p > b.x + p &&
      a.y + p < b.y + b.h - p &&
      a.y + a.h - p > b.y + p
    );
  }

  function loop() {
    if (!running) return;
    update();
    draw();
    raf = requestAnimationFrame(loop);
  }

  function update() {
    if (gameOver) return;
    frame++;

    speed += ACCELERATION;
    if (speed > MAX_SPEED) speed = MAX_SPEED;

    if (frame % 6 === 0) score++;

    if (score >= 500 && !starEarned) {
      starEarned = true;
      chrome.storage.local.set({ "tarn.gameStar": true });
      chrome.runtime.sendMessage({ type: 'GAME_STAR' }).catch(() => {});
    }

    // Player physics
    if (!player.grounded) {
      player.vy += player.ducking ? GRAVITY * SPEED_DROP_COEFF : GRAVITY;
      player.y += player.vy;
      if (player.y >= GROUND_Y - PLAYER_H) {
        player.y = GROUND_Y - PLAYER_H;
        player.vy = 0;
        player.grounded = true;
      }
    } else if (player.ducking) {
      player.y = GROUND_Y - DUCK_H;
    } else {
      player.y = GROUND_Y - PLAYER_H;
    }

    // Run animation: 10 frames per sprite change (slower = smoother looking)
    animTimer++;
    if (animTimer >= 12) {
      animTimer = 0;
      animFrame = (animFrame + 1) % 4;
    }

    groundOffset = (groundOffset + speed) % 20;

    obstacleTimer++;
    const spawnAt = Math.max(70, 140 - score / 10);
    if (obstacleTimer >= spawnAt) {
      obstacleTimer = 0;
      spawnObstacle();
    }

    const playerBox = player.ducking
      ? { x: player.x, y: player.y, w: DUCK_W, h: DUCK_H }
      : { x: player.x, y: player.y, w: PLAYER_W, h: PLAYER_H };

    for (let i = obstacles.length - 1; i >= 0; i--) {
      const ob = obstacles[i];
      ob.x -= speed;
      if (ob.type === 'bird') ob.animTimer = (ob.animTimer || 0) + 1;
      if (checkCollision(playerBox, ob)) { endGame(); return; }
      if (ob.x + ob.w < -20) obstacles.splice(i, 1);
    }
  }

  function endGame() {
    gameOver = true;
    if (score > highScore) {
      highScore = score;
      chrome.storage.local.set({ "tarn.gameHighScore": highScore });
    }
  }

  function draw() {
    ctx.clearRect(0, 0, CANVAS_W, CANVAS_H);

    ctx.fillStyle = '#0C0C0C';
    ctx.fillRect(0, 0, CANVAS_W, CANVAS_H);

    ctx.strokeStyle = '#3A3A3A';
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(0, GROUND_Y);
    ctx.lineTo(CANVAS_W, GROUND_Y);
    ctx.stroke();

    ctx.fillStyle = '#2A2A2A';
    for (let i = -20; i < CANVAS_W + 20; i += 20) {
      ctx.fillRect(i - groundOffset, GROUND_Y + 5, 3, 3);
    }

    // Obstacles
    for (const ob of obstacles) {
      if (ob.type === 'cactus') {
        if (!cropDraw('cactusSprite',
          CACTUS_CONTENT.x, CACTUS_CONTENT.y, CACTUS_CONTENT.w, CACTUS_CONTENT.h,
          ob.x, ob.y, ob.w, ob.h)) {
          ctx.fillStyle = '#CC0000';
          ctx.fillRect(ob.x + 2, ob.y, ob.w - 4, ob.h);
          ctx.fillRect(ob.x - 3, ob.y + 8, 5, 10);
          ctx.fillRect(ob.x + ob.w - 2, ob.y + 14, 5, 10);
        }
      } else if (ob.type === 'bird') {
        const flap = Math.sin((ob.animTimer || 0) * 0.2) * 5;
        if (!cropDraw('birdSprite',
          BIRD_CONTENT.x, BIRD_CONTENT.y, BIRD_CONTENT.w, BIRD_CONTENT.h,
          ob.x, ob.y + flap, ob.w, ob.h)) {
          ctx.fillStyle = '#CC0000';
          ctx.fillRect(ob.x, ob.y + 6, ob.w, ob.h - 6);
        }
      }
    }

    drawPlayer();

    ctx.font = '13px "Press Start 2P", monospace';
    ctx.fillStyle = '#888';
    ctx.textAlign = 'right';
    ctx.fillText(String(score).padStart(5, '0'), CANVAS_W - 16, 24);
    if (highScore > 0) {
      ctx.fillStyle = '#555';
      ctx.font = '10px "Press Start 2P", monospace';
      ctx.fillText('HI ' + String(highScore).padStart(5, '0'), CANVAS_W - 16, 40);
    }

    if (gameOver) {
      ctx.fillStyle = 'rgba(12,12,12,0.8)';
      ctx.fillRect(0, 0, CANVAS_W, CANVAS_H);
      ctx.textAlign = 'center';
      ctx.font = '20px "Press Start 2P", monospace';
      ctx.fillStyle = '#FF0000';
      ctx.fillText('GAME OVER', CANVAS_W / 2, CANVAS_H / 2 - 20);
      ctx.font = '11px "Press Start 2P", monospace';
      ctx.fillStyle = '#888';
      ctx.fillText('SPACE / TAP TO RETRY', CANVAS_W / 2, CANVAS_H / 2 + 8);
      if (starEarned) {
        ctx.fillStyle = '#FFD700';
        ctx.fillText('\u2605 STAR EARNED \u2605', CANVAS_W / 2, CANVAS_H / 2 + 32);
      }
    }
  }

  function drawPlayer() {
    ctx.imageSmoothingEnabled = true;
    ctx.imageSmoothingQuality = 'high';

    const runFrames = [sprites.run1, sprites.run2, sprites.run3, sprites.run4];
    const bbox = RUN_BBOX[animFrame];
    const curFrame = runFrames[animFrame];

    if (player.ducking && player.grounded) {
      // ── DUCK: split sprite CONTENT in half, torso slides onto legs ──
      // Source sprite is 720×720, content at (bbox.x, bbox.y) size (bbox.w, bbox.h)
      // Split content at midY = bbox.y + bbox.h/2
      // Bottom half (legs): draw at ground level
      // Top half (torso): draw overlapping on top of legs
      const src = curFrame || sprites.run1;
      if (src && src.naturalWidth > 1) {
        const midY = bbox.y + bbox.h / 2;
        const halfH = bbox.h / 2;

        // Bottom half (legs) → at ground level, full duck width
        ctx.drawImage(src,
          bbox.x, midY, bbox.w, halfH,
          player.x, GROUND_Y - DUCK_H, DUCK_W, DUCK_H / 2
        );
        // Top half (torso) → slides DOWN onto legs, overlapping
        ctx.drawImage(src,
          bbox.x, bbox.y, bbox.w, halfH,
          player.x + 2, GROUND_Y - DUCK_H + DUCK_H / 2 - 2, DUCK_W - 4, DUCK_H / 2
        );
      } else {
        ctx.fillStyle = '#00FF00';
        ctx.fillRect(player.x, GROUND_Y - DUCK_H, DUCK_W, DUCK_H);
      }
    } else if (!player.grounded) {
      // JUMP
      const src = sprites.jump || sprites.run1;
      if (src && src.naturalWidth > 1) {
        ctx.drawImage(src,
          JUMP_BBOX.x, JUMP_BBOX.y, JUMP_BBOX.w, JUMP_BBOX.h,
          player.x, player.y, PLAYER_W, PLAYER_H
        );
      } else {
        ctx.fillStyle = '#00FF00';
        ctx.fillRect(player.x, player.y, PLAYER_W, PLAYER_H);
      }
    } else {
      // RUN — cycle through 4 frames with individual bboxes
      const src = curFrame || sprites.run1;
      if (src && src.naturalWidth > 1) {
        ctx.drawImage(src,
          bbox.x, bbox.y, bbox.w, bbox.h,
          player.x, player.y, PLAYER_W, PLAYER_H
        );
      } else {
        ctx.fillStyle = '#00FF00';
        ctx.fillRect(player.x, player.y, PLAYER_W, PLAYER_H);
      }
    }
  }

  return {
    init, start, stop,
    jump, duckStart, duckEnd,
    isActive: () => running,
    getScore: () => score,
    isStarEarned: () => starEarned
  };
})();
