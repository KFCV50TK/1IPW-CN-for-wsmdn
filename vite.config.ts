import { defineConfig, loadEnv, type ProxyOptions } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath, URL } from 'node:url'

type DevProxyMap = Record<string, string | ProxyOptions>

function protectedNodeProxy(target: string, key: string, prefix: RegExp): ProxyOptions {
  return {
    target,
    changeOrigin: true,
    rewrite: (path) => path.replace(prefix, ''),
    configure(proxy) {
      proxy.on('proxyReq', (proxyRequest) => {
        if (key) proxyRequest.setHeader('Authorization', `Bearer ${key}`)
      })
    },
  }
}

function addNodeProxy(
  proxy: DevProxyMap,
  env: Record<string, string>,
  route: string,
  envPrefix: string,
  rewritePrefix: RegExp,
) {
  const target = env[`${envPrefix}_TARGET`]?.trim()
  if (!target) return
  proxy[route] = protectedNodeProxy(target, env[`${envPrefix}_KEY`]?.trim() || '', rewritePrefix)
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const proxy: DevProxyMap = {
    '/api': {
      target: env.IPW_DEV_API_TARGET || 'http://127.0.0.1:8080',
      changeOrigin: true,
      rewrite: (path) => path.replace(/^\/api/, ''),
    },
  }

  addNodeProxy(proxy, env, '/speed-node', 'IPW_DEV_SPEED_NODE', /^\/speed-node/)
  addNodeProxy(proxy, env, '/shiyan-node', 'IPW_DEV_SHIYAN_NODE', /^\/shiyan-node/)
  addNodeProxy(proxy, env, '/hongkong2-node', 'IPW_DEV_HONGKONG2_NODE', /^\/hongkong2-node/)
  addNodeProxy(proxy, env, '/jdcloud-node', 'IPW_DEV_JDCLOUD_NODE', /^\/jdcloud-node/)
  addNodeProxy(proxy, env, '/manage-node/zaozhuang', 'IPW_DEV_ZAOZHUANG_NODE', /^\/manage-node\/zaozhuang/)
  addNodeProxy(proxy, env, '/manage-node/hongkong', 'IPW_DEV_HONGKONG_NODE', /^\/manage-node\/hongkong/)

  return {
    plugins: [react()],
    resolve: {
      alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
    },
    server: {
      host: env.IPW_DEV_HOST || '127.0.0.1',
      port: Number(env.IPW_DEV_PORT || 5174),
      proxy,
    },
    build: {
      outDir: 'dist',
      sourcemap: false,
      // React 与 TDesign 版本稳定，拆成独立 chunk 后业务代码更新不会让用户重下这部分。
      rollupOptions: {
        output: {
          // ?????????????????? TDesign ????? tdesign chunk?
          // ????????????????????????? CSS ?????
          manualChunks(id) {
            if (id.includes('node_modules/tdesign-react/es/') || id.includes('node_modules/tdesign-icons-react/')) {
              return 'tdesign'
            }
            if (
              id.includes('node_modules/react') ||
              id.includes('node_modules/react-dom') ||
              id.includes('node_modules/react-router')
            ) {
              return 'react'
            }
            return undefined
          },
        },
      },
      chunkSizeWarningLimit: 900,
    },
  }
})
