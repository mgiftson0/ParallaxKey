const path = require('path');
const CopyPlugin = require('copy-webpack-plugin');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');

module.exports = (env, argv) => {
  const isProduction = argv.mode === 'production';

  return {
    entry: {
      'background/service-worker': './src/background/service-worker.ts',
      'content/content-script': './src/content/content-script.ts',
      'popup/popup': './src/popup/popup.ts',
      'options/options': './src/options/options.ts',
      'devtools/devtools': './src/devtools/devtools.ts',
      'devtools/panel': './src/devtools/panel.ts',
    },
    output: {
      path: path.resolve(__dirname, 'dist'),
      filename: '[name].js',
      clean: true,
    },
    module: {
      rules: [
        {
          test: /\.ts$/,
          use: 'ts-loader',
          exclude: /node_modules/,
        },
        {
          test: /\.css$/,
          use: [MiniCssExtractPlugin.loader, 'css-loader'],
        },
      ],
    },
    resolve: {
      extensions: ['.ts', '.js'],
      alias: {
        '@': path.resolve(__dirname, 'src'),
        '@scanners': path.resolve(__dirname, 'src/scanners'),
        '@core': path.resolve(__dirname, 'src/core'),
        '@utils': path.resolve(__dirname, 'src/utils'),
        '@types': path.resolve(__dirname, 'src/types'),
        '@background': path.resolve(__dirname, 'src/background'),
        '@content': path.resolve(__dirname, 'src/content'),
        '@data': path.resolve(__dirname, 'data'),
      },
    },
    plugins: [
      new MiniCssExtractPlugin({
        filename: '[name].css',
      }),
      new CopyPlugin({
        patterns: [
          { from: 'manifest.json', to: '../manifest.json' },
          { from: 'src/popup/popup.html', to: 'popup/popup.html' },
          { from: 'src/popup/popup.css', to: 'popup/popup.css' },
          { from: 'src/options/options.html', to: 'options/options.html' },
          { from: 'src/options/options.css', to: 'options/options.css' },
          { from: 'src/devtools/devtools.html', to: 'devtools/devtools.html' },
          { from: 'src/devtools/panel.html', to: 'devtools/panel.html' },
          { from: 'src/assets', to: 'assets' },
          { from: 'data', to: 'data' },
        ],
      }),
    ],
    devtool: isProduction ? false : 'inline-source-map',
    optimization: {
      minimize: isProduction,
    },
  };
};