import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { ConfigProvider, theme } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import './index.css'
import App from './App.jsx'
import { AuthProvider } from './context/AuthContext.jsx'

// Cryptographic Vault theme — antd tokens mapped to the CSS variable system.
const vaultTheme = {
  algorithm: theme.darkAlgorithm,
  token: {
    colorPrimary: '#d4a85a',
    colorInfo: '#d4a85a',
    colorSuccess: '#4e9f6d',
    colorError: '#c8553d',
    colorWarning: '#e5b36b',
    colorLink: '#6db8d8',
    colorTextBase: '#f3efe4',
    colorBgBase: '#11141a',
    colorBgContainer: '#1c212a',
    colorBgElevated: '#161a21',
    colorBgLayout: '#0f1218',
    colorBorder: '#353c49',
    colorBorderSecondary: '#262c37',
    colorText: '#f3efe4',
    colorTextSecondary: '#c9c2ad',
    colorTextTertiary: '#9a9382',
    colorTextQuaternary: '#6f6a5d',
    fontFamily: "'Schibsted Grotesk', 'PingFang SC', 'Microsoft YaHei', sans-serif",
    fontSize: 14,
    borderRadius: 8,
    borderRadiusLG: 12,
    borderRadiusSM: 5,
    wireframe: false,
    controlHeight: 38,
    controlHeightLG: 46,
  },
  components: {
    Layout: {
      headerBg: 'transparent',
      bodyBg: 'transparent',
      headerHeight: 64,
      headerPadding: '0 24px',
    },
    Menu: {
      itemBg: 'transparent',
      itemColor: '#9a9382',
      itemSelectedColor: '#f3efe4',
      itemSelectedBg: 'transparent',
      horizontalItemSelectedColor: '#f3efe4',
      itemHoverBg: 'transparent',
      itemHoverColor: '#f3efe4',
      activeBarHeight: 0,
      activeBarBorderWidth: 0,
      itemPaddingInline: 8,
    },
    Card: {
      colorBgContainer: '#161a21',
      colorBorderSecondary: '#262c37',
      borderRadiusLG: 12,
      headerBg: 'transparent',
      headerFontSize: 16,
      paddingLG: 24,
    },
    Button: {
      primaryShadow: '0 8px 24px rgba(184, 137, 62, 0.25)',
      defaultBg: '#1c212a',
      defaultBorderColor: '#353c49',
      fontWeight: 500,
    },
    Input: {
      colorBgContainer: '#11141a',
      activeBorderColor: '#d4a85a',
      hoverBorderColor: '#4a5263',
    },
    Steps: {
      colorPrimary: '#d4a85a',
      colorText: '#f3efe4',
      colorTextDescription: '#9a9382',
      colorTextTertiary: '#6f6a5d',
    },
    Statistic: {
      colorText: '#f3efe4',
      contentFontSize: 32,
    },
    Alert: {
      borderRadiusLG: 8,
    },
    Descriptions: {
      colorText: '#f3efe4',
      colorSplit: '#262c37',
    },
    Tag: {
      borderRadiusSM: 999,
    },
  },
}

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <BrowserRouter>
      <ConfigProvider locale={zhCN} theme={vaultTheme}>
        <AuthProvider>
          <App />
        </AuthProvider>
      </ConfigProvider>
    </BrowserRouter>
  </StrictMode>,
)
