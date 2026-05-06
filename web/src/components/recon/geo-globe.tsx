"use client"

import * as React from "react"
import createGlobe from "cobe"

// ISO 3166-1 alpha-2 → [lat, lng] centroids
const COORDS: Record<string, [number, number]> = {
  US: [37.09, -95.71],   DE: [51.17,  10.45],   GB: [55.38,  -3.44],
  FR: [46.23,   2.21],   JP: [36.20, 138.25],   CN: [35.86, 104.20],
  NL: [52.13,   5.29],   SG: [ 1.35, 103.82],   AU: [-25.27, 133.78],
  CA: [56.13, -106.35],  SE: [60.13,  18.64],   NO: [60.47,   8.47],
  FI: [61.92,  25.75],   CH: [46.82,   8.23],   IE: [53.41,  -8.24],
  IN: [20.59,  78.96],   BR: [-14.24, -51.93],  RU: [61.52, 105.32],
  KR: [35.91, 127.77],   HK: [22.40, 114.11],   TW: [23.70, 121.00],
  IT: [41.87,  12.57],   ES: [40.46,  -3.75],   PL: [51.92,  19.15],
  CZ: [49.82,  15.47],   AT: [47.52,  14.55],   BE: [50.50,   4.47],
  DK: [56.26,   9.50],   ZA: [-30.56,  22.94],  MX: [23.63, -102.55],
  AR: [-38.42, -63.62],  TR: [38.96,  35.24],   UA: [48.38,  31.17],
  IL: [31.05,  34.85],   AE: [23.42,  53.85],   TH: [15.87, 100.99],
  ID: [-0.79, 113.92],   MY: [ 2.11, 112.45],   PH: [12.88, 121.77],
  VN: [14.06, 108.28],   NZ: [-40.90, 174.89],  PT: [39.40,  -8.22],
  RO: [45.94,  24.97],   HU: [47.16,  19.50],   GR: [39.07,  21.82],
  LU: [49.82,   6.13],   IS: [64.96, -19.02],   CL: [-35.68, -71.54],
  CO: [ 4.57, -74.30],   EG: [26.82,  30.80],   SA: [23.89,  45.08],
  PK: [30.38,  69.35],   NG: [ 9.08,   8.68],   KE: [-0.02,  37.91],
  BG: [42.73,  25.49],   HR: [45.10,  15.20],   LT: [55.17,  23.88],
  LV: [56.88,  24.60],   EE: [58.60,  25.01],   SK: [48.67,  19.70],
  RS: [44.02,  21.01],   BY: [53.71,  27.95],   KZ: [48.02,  66.92],
}

const NAMES: Record<string, string> = {
  US: "United States",   DE: "Germany",          GB: "United Kingdom",
  FR: "France",          JP: "Japan",            CN: "China",
  NL: "Netherlands",     SG: "Singapore",        AU: "Australia",
  CA: "Canada",          SE: "Sweden",           NO: "Norway",
  FI: "Finland",         CH: "Switzerland",      IE: "Ireland",
  IN: "India",           BR: "Brazil",           RU: "Russia",
  KR: "South Korea",     HK: "Hong Kong",        TW: "Taiwan",
  IT: "Italy",           ES: "Spain",            PL: "Poland",
  CZ: "Czech Republic",  AT: "Austria",          BE: "Belgium",
  DK: "Denmark",         ZA: "South Africa",     MX: "Mexico",
  AR: "Argentina",       TR: "Turkey",           UA: "Ukraine",
  IL: "Israel",          AE: "UAE",              TH: "Thailand",
  ID: "Indonesia",       MY: "Malaysia",         PH: "Philippines",
  VN: "Vietnam",         NZ: "New Zealand",      PT: "Portugal",
  RO: "Romania",         HU: "Hungary",          GR: "Greece",
  LU: "Luxembourg",      IS: "Iceland",          CL: "Chile",
  CO: "Colombia",        EG: "Egypt",            SA: "Saudi Arabia",
  PK: "Pakistan",        NG: "Nigeria",          KE: "Kenya",
  BG: "Bulgaria",        HR: "Croatia",          LT: "Lithuania",
  LV: "Latvia",          EE: "Estonia",          SK: "Slovakia",
  RS: "Serbia",          BY: "Belarus",          KZ: "Kazakhstan",
}

export function extractCountry(asn: string): string | null {
  if (!asn) return null
  // handles "[AS15169 Google LLC, US]" and "AS15169 Google LLC, US"
  const m = asn.match(/,\s*([A-Z]{2})[\s\]]*$/)
  return m ? m[1] : null
}

const GLOBE_SIZE = 240

interface GeoGlobeProps {
  countries: { code: string; count: number }[]
}

export function GeoGlobe({ countries }: GeoGlobeProps) {
  const canvasRef = React.useRef<HTMLCanvasElement>(null)
  const phiRef = React.useRef(0)

  const visible = countries.filter(({ code }) => COORDS[code])
  const markersKey = visible.map((c) => c.code + c.count).join(",")

  React.useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas || !visible.length) return

    const markers = visible.map(({ code, count }) => ({
      location: COORDS[code] as [number, number],
      size: Math.min(0.13, 0.04 + count * 0.025),
    }))

    const globe = createGlobe(canvas, {
      devicePixelRatio: 2,
      width: GLOBE_SIZE * 2,
      height: GLOBE_SIZE * 2,
      phi: phiRef.current,
      theta: 0.3,
      dark: 1,
      diffuse: 1.2,
      mapSamples: 16000,
      mapBrightness: 7,
      baseColor: [0.07, 0.07, 0.07],
      markerColor: [0.9, 0.9, 0.9],
      glowColor: [0.04, 0.04, 0.04],
      markers,
    })

    let animId: number
    function tick() {
      phiRef.current += 0.003
      globe.update({ phi: phiRef.current })
      animId = requestAnimationFrame(tick)
    }
    animId = requestAnimationFrame(tick)

    return () => {
      cancelAnimationFrame(animId)
      globe.destroy()
    }
  // markersKey is a stable string dep; phiRef and visible are intentionally excluded
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [markersKey])

  if (!visible.length) return null

  const sorted = [...countries].sort((a, b) => b.count - a.count)

  return (
    <div className="border border-border bg-card">
      <div className="px-4 py-2 border-b border-border">
        <span className="font-mono text-xs tracking-widest text-muted-foreground">
          {"// INFRASTRUCTURE GEO"}{" "}
          <span className="text-muted-foreground-3">[{visible.length} countr{visible.length === 1 ? "y" : "ies"}]</span>
        </span>
      </div>
      <div className="flex flex-col sm:flex-row">
        <div className="flex items-center justify-center p-4 shrink-0">
          <canvas
            ref={canvasRef}
            style={{ width: GLOBE_SIZE, height: GLOBE_SIZE }}
          />
        </div>
        <div className="border-t sm:border-t-0 sm:border-l border-border p-4 flex-1 min-w-0 flex flex-col justify-center">
          <div className="font-mono text-micro text-muted-foreground mb-2 tracking-widest">NODES</div>
          <div className="space-y-0.5 max-h-[180px] overflow-y-auto">
            {sorted.map(({ code, count }) => (
              <div key={code} className="flex items-center justify-between gap-4 font-mono text-data py-0.5">
                <span className="text-muted-foreground-2 truncate">
                  {NAMES[code] ?? code}
                </span>
                <span className="text-muted-foreground-3 tabular-nums shrink-0">[{count}]</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}