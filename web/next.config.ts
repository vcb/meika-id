import type { NextConfig } from "next";
import path from "path";

const nextConfig: NextConfig = {
  transpilePackages: ["../lib"],
  webpack: (config, { isServer }) => {
    // Allow importing from parent directory
    config.resolve.modules.push(path.resolve("../"));
    
    // Add path aliases
    config.resolve.alias = {
      ...config.resolve.alias,
      "@lib": path.resolve("../lib")
    };
    
    return config;
  },
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: 'http://localhost:3000/api/:path*'
      }
    ]
  }
};

export default nextConfig;
