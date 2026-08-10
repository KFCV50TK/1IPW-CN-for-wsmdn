import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { ConfigProvider } from 'tdesign-react'
import zhCN from 'tdesign-react/es/locale/zh_CN'
import App from './App'
import 'tdesign-react/es/style/index.css'
import './styles.css'

const initialTheme = window.localStorage.getItem('ipw-theme') === 'dark' ? 'dark' : 'light'
document.documentElement.dataset.theme = initialTheme
document.documentElement.classList.toggle('dark', initialTheme === 'dark')
document.documentElement.setAttribute('theme-mode', initialTheme)
document.documentElement.style.colorScheme = initialTheme

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ConfigProvider globalConfig={zhCN}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </ConfigProvider>
  </React.StrictMode>,
)
