import QrCode from "qrcode";
export async function drawQRToCanvas(
  canvas: HTMLCanvasElement,
  text: string,
  size = 192,
) {
  await QrCode.toCanvas(canvas, text, { width: size });
}
