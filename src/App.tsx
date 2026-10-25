/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export default function App() {
  return (
    <div className="w-screen h-screen overflow-hidden bg-[#0a0e17]">
      <iframe
        src="/sim/index.html"
        title="Sentinel-X Interactive 3D Simulation"
        className="w-full h-full border-0"
        allow="accelerometer; gyroscope; autoplay"
      />
    </div>
  );
}
