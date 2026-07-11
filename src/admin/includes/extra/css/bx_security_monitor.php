<?php 
  defined('_VALID_XTC') or die('Direct Access to this location is not allowed.');

  if (basename($_SERVER['PHP_SELF']) == 'bx_security_monitor.php') {
?>
<style>

  /* BX Attribute Lock Admin Styles */

  #headboard {
    display: flex; 
    flex-direction: row; 
    justify-content: flex-start;
    width: 100%;
    align-items: center; 
    background: #AF417E; 
    color: #ffffff; 
    border-radius: 4px; 
    margin-bottom: 10px; 
    padding: 4px 0 2px 0;
    line-height: 30px;
  }

  #headboard .main {
    margin: 5px 10px;
  }

  .fixed_messageStack {
    position: fixed;
    top: 88px;
    left: 50%;
    transform: translateX(-50%);
    z-index: 1000;
    width: 80%;
    padding: 10px 0;
    text-align: center;
    display: none;
  }

  .SumoSelect {
    width: 100%;
  }
  
  table, th, td {
    font: inherit;
  }

  .scroll-target {
    scroll-margin-top: 88px;
  }

  .warning_message,
  .success_message {
    border-radius: 4px;
    margin-right: 5px;
  }

  .msec-box {
      background:#fff;
      border:1px solid #ddd;
      border-radius:9px;
      margin: 1rem 0.5rem 0 0.5rem;
      overflow:hidden
  }
  .msec-box-title {
      background: #f2f2f2;
      padding: 11px 13px;
      font-weight: 800
  }

  .msec-box-title.pastel-apricot {
    background: #ffe7d6;
    color: #6f3e1f;
    border-bottom: 1px solid #f4c7a7;
  }

  .msec-box-title.pastel-mint {
    background: #dff5ea;
    color: #245642;
    border-bottom: 1px solid #b8e2cf;
  }

  .msec-box-title.pastel-sky {
    background: #e3f1ff;
    color: #254a66;
    border-bottom: 1px solid #bdd9f3;
  }

  .msec-box-title.pastel-lavender {
    background: #eee6fb;
    color: #4b3d6b;
    border-bottom: 1px solid #d3c2ef;
  }

  .msec-box-title.pastel-rose {
    background: #ffe4ea;
    color: #6a3140;
    border-bottom: 1px solid #f2bcc8;
  }

  .msec-box-title.pastel-lemon {
    background: #fff4cc;
    color: #5f4e1d;
    border-bottom: 1px solid #eadb9e;
  }

  .msec-box-body {
    padding:13px
  }

  .msec-info {
    background:#eef4fb;
    border:1px solid #c6d8ed;
    color:#344b63;
    padding:11px 13px;
    border-radius:7px;
    margin: 1rem 0 0.5rem 0;
    line-height:1.5
  }

  .msec-warning {
    background:#fff7e5;
    border:1px solid #f0d59c;
    color:#6b4b00;
    padding:11px 13px;
    border-radius:7px;
    margin-bottom:15px
  }

  .msec-grid {
    display:grid;
    grid-template-columns:repeat(2,minmax(0,1fr));
    gap:18px;
    margin: 1rem 0.5rem 0 0.5rem;
  }

  .msec-grid .msec-box {
    margin: 0;
  }

  .msec-cards {
    display:grid;
    grid-template-columns:repeat(6,minmax(125px,1fr));
    gap:11px;
    margin: 1rem 0.5rem 0 0.5rem;
  }

  .msec-card {
    background:#fff;
    border:1px solid #ddd;
    border-radius:9px;
    padding:14px;
}

  .msec-card-label {
    font-size:12px;
    color:#666;
    margin-bottom:7px
  }

  .msec-card-value {
    font-size:26px;
    font-weight:800;
    color:#b40001;
    text-align: center;
}

  .msec-state {
    padding:18px;
    border-radius:10px;
    color:#fff;
    margin: 1rem 0.5rem 0 0.5rem;
  }

  .msec-state-low {
      background:linear-gradient(135deg,#1f6f38,#2f9250)
  }

  .msec-state-medium {
    background:linear-gradient(135deg,#936000,#c78a12)
  }

  .msec-state-high {
    background:linear-gradient(135deg,#8e0000,#c10000)
  }

  .msec-state small {
    display:block;
    text-transform:uppercase;
    letter-spacing:.08em;
    opacity:.85
  }

  .msec-state strong {
    display:block;
    font-size:28px;
    margin:5px 0
  }

  .msec-table {
      width:100%;
      border-collapse:collapse
  }

  .msec-table th,
  .msec-table td {
      padding: 8px 9px;
      border-top: 1px solid #eee;
      text-align: left;
  }

  .msec-table th {
      background:#fafafa;
      white-space:nowrap
  }

  .msec-path {
      font-family:Consolas,Monaco,monospace;
      word-break:break-word
  }

  .msec-small {
      font-size:12px;
      color:#777
  }

  .msec-actions {
      display:flex;
      gap:5px;
      flex-wrap:wrap
  }

  .msec-button,
  .msec-actions button {
      display:inline-block;
      border:0;
      background:#b40001;
      color:#fff;
      padding:7px 10px;
      border-radius:4px;
      cursor:pointer;
      text-decoration:none;
      font-weight:700
  }

  .msec-button.secondary,
  .msec-actions button.secondary {
      background:#555
  }

  .msec-button.light,
  .msec-actions button.light {
      background:#777
  }

  .msec-form-row {
      display: flex;
      gap: 10px;
      align-items: flex-start;
      flex-wrap: wrap
  }

  .msec-form-row label {
      display:block;
      font-weight:700;
      margin-bottom:4px
  }

  .msec-form-row select {
      padding:7px;
      min-width:180px
  }

  .msec-settings {
      display:grid;
      grid-template-columns: repeat(5, minmax(200px,1fr));
      gap:12px
  }

  .msec-settings > div > label {
      font-weight: 700;
      display: block;
      margin-bottom: 6px
  }

  .msec-form-row .SumoSelect label,
  .msec-settings .SumoSelect label {
    font-weight: normal;
    display: inline;
    margin-bottom: 0;
}

  .msec-badge {
      display:inline-block;
      padding:4px 8px;
      border-radius:12px;
      font-size:11px;
      font-weight:800
  }

  .msec-badge-red {
      background:#f5dada;
      color:#940000
  }

  .msec-badge-green {
      background:#e3f3e7;
      color:#1d6f35
  }

  .msec-badge-grey {
      background:#eee;
      color:#555
  }

  .msec-bars-row {
      display:grid;
      grid-template-columns:minmax(160px,1.4fr) minmax(100px,2fr) 50px;
      gap:8px;
      align-items:center;
      margin-bottom:9px
  }

  .msec-bar-track {
      height:10px;
      background:#ececec;
      border-radius:10px;
      overflow:hidden
  }

  .msec-bar {
      height:100%;
      background:#b40001;
      border-radius:10px
  }

  .msec-alert {
      border-left:5px solid #c78a12;
      background:#fff8e8;
      padding:10px 12px;
      border-radius:6px;
      margin-bottom:8px
  }

  .msec-alert.high {
      border-left-color:#b40001;
      background:#fff0f0
  }

  .msec-chart {
      height:165px;
      display:flex;
      align-items:flex-end;
      gap:4px;
      border-bottom:1px solid #ccc
  }

  .msec-chart-col {
      flex:1;
      height:100%;
      display:flex;
      flex-direction:column;
      justify-content:flex-end;
      align-items:center;
      position:relative
  }

  .msec-chart-bar {
      width:100%;
      max-width:18px;
      min-height:2px;
      background:#b40001;
      border-radius:3px 3px 0 0
  }

  .msec-chart-label {
      font-size:9px;
      color:#777;
      height:18px;
      padding-top:3px
  }

  .msec-chart-value {
      position:absolute;
      top:0;
      font-size:9px;
      color:#555
  }

  .msec-install {
      max-width:760px;
      margin:30px auto
  }

  .msec-install h2 {
      margin-top:0
  }

  .msec-divider {
      height:1px;
      background:#eee;
      margin: 1rem 0.5rem 0 0.5rem;
  }

  @media(max-width:1200px) {
      .msec-cards {
          grid-template-columns:repeat(3,minmax(125px,1fr))
      }

      .msec-settings {
          grid-template-columns:repeat(2,minmax(190px,1fr))
      }
  }

  @media(max-width:900px) {
      .msec-grid {
          grid-template-columns:1fr
      }

      .msec-cards {
          grid-template-columns:repeat(2,minmax(125px,1fr))
      }
  }

  @media(max-width:560px) {
      .msec-cards,
      .msec-settings {
          grid-template-columns:1fr
      }

      .msec-bars-row {
          grid-template-columns:1fr 80px 40px
      }
  }
</style>
<?php } ?>