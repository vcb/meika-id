const path = require('path');
const CopyPlugin = require('copy-webpack-plugin');
const webpack = require('webpack');

module.exports = {
  entry: {
    popup: './src/popup/index.tsx',
    'content-script': './src/content-script.ts',
    background: './src/background.ts',
    'vault-worker': './src/vault-worker.ts',
    setup: './src/setup/index.tsx',
    login: './src/login/index.tsx',
    'witness-worker': './src/witness-worker.ts'
  },
  output: {
    path: path.resolve(__dirname, 'build'),
    filename: '[name].bundle.js',
    globalObject: 'self', // Critical for Web Workers and Comlink
  },
  module: {
    rules: [
      {
        test: /\.(ts|tsx)$/,
        exclude: /node_modules/,
        use: [
          {
            loader: 'babel-loader',
            options: {
              presets: [
                '@babel/preset-env',
                '@babel/preset-react',
                '@babel/preset-typescript'
              ]
            }
          },
          {
            loader: 'ts-loader'
          }
        ]
      },
      {
        test: /\.(js|jsx)$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: ['@babel/preset-env', '@babel/preset-react']
          }
        }
      },
      {
        test: /\.css$/,
        use: ['style-loader', 'css-loader']
      }
    ]
  },
  plugins: [
    new CopyPlugin({
      patterns: [
        { from: 'src/popup/popup.html', to: 'popup.html' },
        { from: 'src/popup/popup.css', to: 'popup.css' },
        { from: 'src/setup/setup.html', to: 'setup.html' },
        { from: 'src/setup/setup.css', to: 'setup.css' },
        { from: 'src/login/login.html', to: 'login.html' },
        { from: 'src/login/login.css', to: 'login.css' },
        { from: 'src/proving/meika-login.wasm', to: 'meika-login.wasm' },
        { from: 'src/proving/meika-login.zkey', to: 'meika-login.zkey' },
      ],
    }),
    new webpack.ProvidePlugin({
      Buffer: ['buffer', 'Buffer'],
      process: require.resolve('process/browser')
    })
  ],
  resolve: {
    extensions: ['.ts', '.tsx', '.js', '.jsx'],
    alias: {
      '@lib': path.resolve(__dirname, '../lib')
    },
    fallback: {
      "fs": false,
      "path": require.resolve("path-browserify"),
      "stream": require.resolve("stream-browserify"),
      "buffer": require.resolve("buffer/"),
      "assert": require.resolve("assert/"),
      "vm": false,
      "crypto": false // Important
    }
  },
  experiments: {
    asyncWebAssembly: true,
  },
  mode: 'development',
  devtool: 'source-map',
};