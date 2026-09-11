import React, { useEffect, useRef, useState } from 'react';
import L from 'leaflet';

const GOOGLE_TILE_LAYERS = {
  roadmap: {
    name: 'Google Roadmap',
    url: 'https://mt{s}.google.com/vt/lyrs=m&x={x}&y={y}&z={z}',
    subdomains: ['0', '1', '2', '3'],
    maxZoom: 19,
    minZoom: 3,
    attribution: '&copy; <a href="https://maps.google.com" target="_blank" rel="noreferrer">Google Maps</a>'
  },
  hybrid: {
    name: 'Google Satellite',
    url: 'https://mt{s}.google.com/vt/lyrs=y&x={x}&y={y}&z={z}',
    subdomains: ['0', '1', '2', '3'],
    maxZoom: 19,
    minZoom: 3,
    attribution: '&copy; <a href="https://maps.google.com" target="_blank" rel="noreferrer">Google Maps Satellite</a>'
  },
  terrain: {
    name: 'Google Terrain',
    url: 'https://mt{s}.google.com/vt/lyrs=p&x={x}&y={y}&z={z}',
    subdomains: ['0', '1', '2', '3'],
    maxZoom: 19,
    minZoom: 3,
    attribution: '&copy; <a href="https://maps.google.com" target="_blank" rel="noreferrer">Google Maps Terrain</a>'
  }
};

export default function MapViewer({ geoResults = [] }) {
  const mapRef = useRef(null);
  const mapInstanceRef = useRef(null);
  const tileLayerRef = useRef(null);
  const [mapType, setMapType] = useState('roadmap'); // 'roadmap', 'hybrid', 'terrain', 'embed'

  const validGeos = geoResults.filter(g => g && typeof g.latitude === 'number' && typeof g.longitude === 'number');
  const firstGeo = validGeos[0] || null;

  const targetLat = firstGeo ? firstGeo.latitude : 37.7749;
  const targetLon = firstGeo ? firstGeo.longitude : -122.4194;
  const googleMapsExternalUrl = firstGeo
    ? `https://www.google.com/maps?q=${firstGeo.latitude},${firstGeo.longitude}`
    : 'https://maps.google.com';

  // Initialize and update Leaflet map
  useEffect(() => {
    if (mapType === 'embed' || !mapRef.current) return;

    let centerLat = 20.0;
    let centerLon = 0.0;
    let defaultZoom = 3;

    if (validGeos.length === 1) {
      centerLat = validGeos[0].latitude;
      centerLon = validGeos[0].longitude;
      defaultZoom = 10;
    } else if (validGeos.length > 1) {
      centerLat = validGeos[0].latitude;
      centerLon = validGeos[0].longitude;
      defaultZoom = 6;
    }

    // Initialize map if not created yet
    if (!mapInstanceRef.current) {
      const map = L.map(mapRef.current, {
        center: [centerLat, centerLon],
        zoom: defaultZoom,
        minZoom: 3,
        maxZoom: 19,
        worldCopyJump: false,
        maxBounds: [
          [-85, -180],
          [85, 180]
        ],
        maxBoundsViscosity: 1.0
      });

      const layerConfig = GOOGLE_TILE_LAYERS[mapType] || GOOGLE_TILE_LAYERS.roadmap;
      const tileLayer = L.tileLayer(layerConfig.url, {
        subdomains: layerConfig.subdomains,
        maxZoom: layerConfig.maxZoom,
        minZoom: layerConfig.minZoom,
        noWrap: true, // Prevents repeating multiple worlds horizontally
        bounds: [
          [-85, -180],
          [85, 180]
        ],
        attribution: layerConfig.attribution
      }).addTo(map);

      tileLayerRef.current = tileLayer;
      mapInstanceRef.current = map;
    } else {
      const map = mapInstanceRef.current;
      map.setMinZoom(3);
      map.setMaxZoom(19);
      map.setMaxBounds([
        [-85, -180],
        [85, 180]
      ]);
      map.setView([centerLat, centerLon], defaultZoom);
    }

    const map = mapInstanceRef.current;

    // Switch Google layer when mapType changes
    if (tileLayerRef.current) {
      map.removeLayer(tileLayerRef.current);
      const layerConfig = GOOGLE_TILE_LAYERS[mapType] || GOOGLE_TILE_LAYERS.roadmap;
      tileLayerRef.current = L.tileLayer(layerConfig.url, {
        subdomains: layerConfig.subdomains,
        maxZoom: layerConfig.maxZoom,
        minZoom: layerConfig.minZoom,
        noWrap: true, // Prevents world repetition
        bounds: [
          [-85, -180],
          [85, 180]
        ],
        attribution: layerConfig.attribution
      }).addTo(map);
    }

    // Remove existing markers & polylines
    map.eachLayer(layer => {
      if (layer instanceof L.Marker || layer instanceof L.Polyline) {
        map.removeLayer(layer);
      }
    });

    const latLngs = [];

    // Custom cyber radar pin
    const cyberIcon = L.divIcon({
      className: 'custom-google-pin',
      html: `
        <div style="position: relative; width: 34px; height: 34px; display: flex; align-items: center; justify-content: center;">
          <div style="
            position: absolute;
            width: 30px;
            height: 30px;
            border-radius: 50%;
            background: rgba(239, 68, 68, 0.4);
            animation: ping 1.8s cubic-bezier(0, 0, 0.2, 1) infinite;
          "></div>
          <div style="
            width: 16px;
            height: 16px;
            background: #ef4444;
            border: 2px solid #ffffff;
            border-radius: 50%;
            box-shadow: 0 0 12px rgba(239, 68, 68, 0.9);
            position: relative;
            z-index: 2;
          "></div>
        </div>
      `,
      iconSize: [34, 34],
      iconAnchor: [17, 17]
    });

    validGeos.forEach(g => {
      const pos = [g.latitude, g.longitude];
      latLngs.push(pos);

      const marker = L.marker(pos, { icon: cyberIcon }).addTo(map);
      const gMapsLink = `https://www.google.com/maps?q=${g.latitude},${g.longitude}`;

      marker.bindPopup(`
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; font-size: 12px; color: #0f172a; line-height: 1.45; min-width: 220px;">
          <div style="display: flex; align-items: center; gap: 6px; margin-bottom: 5px;">
            <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #ef4444;"></span>
            <strong style="color: #0284c7; font-size: 13px;">IP: ${g.ip}</strong>
          </div>
          <div style="margin-bottom: 2px;"><strong>Location:</strong> ${g.city || ''} ${g.region || ''}, ${g.country}</div>
          <div style="margin-bottom: 2px;"><strong>ASN:</strong> ${g.asn || 'N/A'}</div>
          <div style="margin-bottom: 2px;"><strong>ISP:</strong> ${g.isp || 'N/A'}</div>
          <div style="margin-bottom: 6px; color: #64748b; font-size: 11px;">
            <strong>Coords:</strong> ${g.latitude.toFixed(4)}, ${g.longitude.toFixed(4)}
          </div>
          <a href="${gMapsLink}" target="_blank" rel="noreferrer" style="
            display: inline-block;
            background: #2563eb;
            color: #ffffff;
            text-decoration: none;
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
          ">
            Open in Google Maps ↗
          </a>
        </div>
      `);
    });

    // Auto-fit bounds if multiple points, or zoom to single point
    if (latLngs.length > 1) {
      map.fitBounds(L.latLngBounds(latLngs), { padding: [50, 50], maxZoom: 12 });
      L.polyline(latLngs, {
        color: '#38bdf8',
        weight: 3,
        opacity: 0.85,
        dashArray: '6, 8'
      }).addTo(map);
    } else if (latLngs.length === 1) {
      map.setView(latLngs[0], 10);
    }

    // Critical: Force Leaflet to recalculate container dimensions when tab opens
    const timer1 = setTimeout(() => {
      if (mapInstanceRef.current) mapInstanceRef.current.invalidateSize();
    }, 100);
    const timer2 = setTimeout(() => {
      if (mapInstanceRef.current) mapInstanceRef.current.invalidateSize();
    }, 350);

    return () => {
      clearTimeout(timer1);
      clearTimeout(timer2);
    };
  }, [geoResults, mapType]);

  // Clean up Leaflet on unmount or mode toggle
  useEffect(() => {
    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
        tileLayerRef.current = null;
      }
    };
  }, [mapType]);

  return (
    <div style={{ position: 'relative' }}>
      {/* Google Maps Toolbar */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        background: 'rgba(15, 23, 42, 0.9)',
        backdropFilter: 'blur(8px)',
        border: '1px solid rgba(56, 189, 248, 0.25)',
        borderBottom: 'none',
        borderRadius: '8px 8px 0 0',
        padding: '8px 12px',
        gap: '8px',
        flexWrap: 'wrap'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '13px', fontWeight: 600, color: '#38bdf8', display: 'flex', alignItems: 'center', gap: '5px' }}>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path>
              <circle cx="12" cy="10" r="3"></circle>
            </svg>
            Google Maps Infrastructure View
          </span>
          {firstGeo && (
            <span style={{ fontSize: '11px', color: '#94a3b8', background: 'rgba(255,255,255,0.06)', padding: '2px 8px', borderRadius: '4px' }}>
              {firstGeo.city || firstGeo.region || firstGeo.country} ({firstGeo.ip})
            </span>
          )}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          {/* Map Layer Switcher */}
          <button
            onClick={() => setMapType('roadmap')}
            style={{
              background: mapType === 'roadmap' ? '#0284c7' : 'rgba(255, 255, 255, 0.07)',
              color: '#fff',
              border: '1px solid rgba(255, 255, 255, 0.12)',
              borderRadius: '4px',
              padding: '4px 9px',
              fontSize: '11px',
              cursor: 'pointer',
              fontWeight: 600
            }}
          >
            🗺️ Roadmap
          </button>
          <button
            onClick={() => setMapType('hybrid')}
            style={{
              background: mapType === 'hybrid' ? '#0284c7' : 'rgba(255, 255, 255, 0.07)',
              color: '#fff',
              border: '1px solid rgba(255, 255, 255, 0.12)',
              borderRadius: '4px',
              padding: '4px 9px',
              fontSize: '11px',
              cursor: 'pointer',
              fontWeight: 600
            }}
          >
            🛰️ Satellite
          </button>
          <button
            onClick={() => setMapType('embed')}
            style={{
              background: mapType === 'embed' ? '#0284c7' : 'rgba(255, 255, 255, 0.07)',
              color: '#fff',
              border: '1px solid rgba(255, 255, 255, 0.12)',
              borderRadius: '4px',
              padding: '4px 9px',
              fontSize: '11px',
              cursor: 'pointer',
              fontWeight: 600
            }}
          >
            🌐 Google Embed
          </button>

          <a
            href={googleMapsExternalUrl}
            target="_blank"
            rel="noreferrer"
            style={{
              background: 'rgba(37, 99, 235, 0.25)',
              border: '1px solid rgba(59, 130, 246, 0.5)',
              color: '#60a5fa',
              padding: '4px 9px',
              borderRadius: '4px',
              fontSize: '11px',
              textDecoration: 'none',
              fontWeight: 600,
              display: 'flex',
              alignItems: 'center',
              gap: '4px'
            }}
          >
            Open in Google Maps ↗
          </a>
        </div>
      </div>

      {/* Map Display: Google Tiles or Google Embed iframe */}
      {mapType === 'embed' ? (
        <div style={{
          height: '420px',
          borderRadius: '0 0 8px 8px',
          overflow: 'hidden',
          border: '1px solid var(--border-cyan, rgba(56, 189, 248, 0.3))'
        }}>
          <iframe
            title="Google Maps"
            width="100%"
            height="100%"
            style={{ border: 0 }}
            loading="lazy"
            allowFullScreen
            src={`https://maps.google.com/maps?q=${targetLat},${targetLon}&hl=en&z=11&output=embed`}
          />
        </div>
      ) : (
        <div
          ref={mapRef}
          className="map-container"
          style={{
            height: '420px',
            borderRadius: '0 0 8px 8px',
            borderTop: 'none',
            background: '#1e293b'
          }}
        />
      )}

      {/* Legal & Disclaimer Banner */}
      <div className="disclaimer-banner">
        <strong>APPROXIMATE INFRASTRUCTURE GEOLOCATION NOTICE:</strong> Geolocation strictly reflects registered mail relay autonomous systems (ASNs) and hosting servers. Attackers frequently route through VPNs, proxies, or compromised relays; coordinates do not represent a verified physical person's residence.
      </div>
    </div>
  );
}
