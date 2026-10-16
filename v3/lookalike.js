// Void v3: brand lookalike / typosquat detector. Pure text rules, no network.
const BRANDS={
 paypal:["paypal.com","paypal.me","paypal.com.au","paypal.co.uk","paypal.in"],
 google:["google.com","google.cn","google-analytics.com","googletagmanager.com","googleadservices.com","googlesyndication.com","googleapis.cn","googlevideo.com","ggpht.com","google.dev","google.org","withgoogle.com","web.app","firebaseapp.com","googledomains.com","google.co.in","google.co.uk","google.de","google.fr","google.ca","google.com.au","googleapis.com","goo.gl","gstatic.com","googleusercontent.com","googlemail.com"],
 gmail:["gmail.com"],
 microsoft:["microsoft.com","cloud.microsoft","microsoft365.com","msftconnecttest.com","microsoftstore.com","bing.com","skype.com","xbox.com","visualstudio.com","azureedge.net","windowsazure.com","msauth.net","msftauth.net","microsoftonline.com","microsoft.co.in","live.com","office.com","office365.com","outlook.com","msn.com","azure.com","windows.com","sharepoint.com","onedrive.com"],
 outlook:["outlook.com","outlook.live.com","office.com"],
 apple:["apple.com","cdn-apple.com","apple-dns.net","mzstatic.com","apple.news","applecard.apple","icloud.com","apple.co","itunes.com"],
 icloud:["icloud.com"],
 amazon:["amazon.com","amazon-adsystem.com","media-amazon.com","amazon.dev","amazonpay.in","amazonpay.com","amazon.es","amazon.it","amazon.nl","amazon.sg","amazon.ae","amazon.com.br","amazon.com.mx","ssl-images-amazon.com","amazonvideo.com","primevideo.com","amazon.in","amazon.co.uk","amazon.de","amazon.ca","amazon.fr","amazon.co.jp","amazonaws.com","amazon.com.au","amzn.com","amzn.to","amzn.in"],
 facebook:["facebook.com","fb.com","fb.me","facebook.net","fbcdn.net","messenger.com"],
 instagram:["instagram.com"],
 whatsapp:["whatsapp.com","whatsapp.net","wa.me"],
 netflix:["netflix.com","netflix.net"],
 linkedin:["linkedin.com","lnkd.in"],
 twitter:["twitter.com","x.com","t.co"],
 dropbox:["dropbox.com","dropboxapi.com"],
 adobe:["adobe.com","adobe.io","adobelogin.com"],
 docusign:["docusign.com","docusign.net"],
 dhl:["dhl.com","dhl.de","dhl.co.uk","dhl.com.au","dhl.fr"],
 fedex:["fedex.com"],
 usps:["usps.com"],
 chase:["chase.com","jpmorganchase.com","jpmorgan.com"],
 wellsfargo:["wellsfargo.com"],
 bankofamerica:["bankofamerica.com"],
 citibank:["citibank.com","citi.com"],
 coinbase:["coinbase.com"],
 binance:["binance.com","binance.us"],
 metamask:["metamask.io"],
 steam:["steampowered.com","steamcommunity.com","steamstatic.com"],
 discord:["discord.com","discord.gg","discordapp.com"],
 spotify:["spotify.com","scdn.co"],
 yahoo:["yahoo.com","yahoo.co.in","yahoo.co.jp","yahoo.co.uk"],
 ebay:["ebay.com","ebay.in","ebay.co.uk","ebay.de"],
 github:["github.com","github.io","githubusercontent.com"],
 zoom:["zoom.us","zoom.com"],
 telegram:["telegram.org","t.me","telegram.me"],
 hdfcbank:["hdfcbank.com"],
 icicibank:["icicibank.com"],
 sbi:["sbi.co.in","onlinesbi.sbi","onlinesbi.com","sbi.bank.in"],
 paytm:["paytm.com","paytm.in"],
 phonepe:["phonepe.com"],
 flipkart:["flipkart.com"],
 jio:["jio.com"],
 airtel:["airtel.in","airtel.com"],
 charusat:["charusat.ac.in","charusat.edu.in","charusat.online"],
 irs:["irs.gov"],
};
const TWO=new Set(["co","com","org","net","ac","edu","gov","gob","nic"]);
function regDomain(host){const p=host.split(".");if(p.length<=2)return host;const t=p[p.length-1],s=p[p.length-2];return(t.length===2&&TWO.has(s)&&p.length>=3)?p.slice(-3).join("."):p.slice(-2).join(".")}
function norm(s){return s.replace(/vv/g,"w").replace(/rn/g,"m").replace(/0/g,"o").replace(/1/g,"l").replace(/3/g,"e").replace(/5/g,"s").replace(/\$/g,"s")}
function lev(a,b,max){if(Math.abs(a.length-b.length)>max)return max+1;let p=Array.from({length:b.length+1},(_,i)=>i);for(let i=1;i<=a.length;i++){const c=[i];for(let j=1;j<=b.length;j++)c[j]=Math.min(p[j]+1,c[j-1]+1,p[j-1]+(a[i-1]===b[j-1]?0:1));p=c}return p[b.length]}
const NAMES=Object.keys(BRANDS);
// returns {brand,why} or null. host must be lowercase hostname.
function lookalike(host){
 if(!host||/^(\d{1,3}\.){3}\d{1,3}$/.test(host))return null;
 const reg=regDomain(host);
 for(const b of NAMES){for(const d of BRANDS[b]){if(host===d||host.endsWith("."+d))return null}}
 if(/^(google|amazon|apple|microsoft|yahoo|ebay|adobe)\.(com?|net)\.[a-z]{2}$/.test(reg))return null;
 const labels=host.split(".");const regLabel=reg.split(".")[0];
 if(/\.(edu|gov|mil|int)$/.test(host)||/\.(ac|edu|gov|nic)\.[a-z]{2}$/.test(host))return null;
 const tldp=labels[labels.length-1];if(NAMES.includes(tldp)||["microsoft","google","amazon","apple","cloud"].includes(tldp))return null;
 if(host.startsWith("xn--")||labels.some(l=>l.startsWith("xn--")))return {brand:null,why:"punycode (look-alike characters) in the hostname"};
 const hostNoTld=labels.slice(0,-1);
 const toks=[];for(const l of hostNoTld)for(const t of l.split("-"))if(t)toks.push(t);
 for(const b of NAMES){
  if(b.length<4)continue; // short names (sbi, irs) only checked as exact tokens below
  if(toks.includes(b))return {brand:b,why:"contains \""+b+"\" but is not an official "+b+" domain"};
  for(const t of toks){if(t!==b&&norm(t)===b&&t.length>=4)return {brand:b,why:"\""+t+"\" imitates \""+b+"\" (swapped characters)"}}
  const rl=regLabel;
  if(rl.length>=5&&rl!==b){const mx=b.length>=8?2:1;if(lev(norm(rl),b,mx)<=mx||lev(rl,b,mx)<=mx)return {brand:b,why:"\""+rl+"\" is one or two typos away from \""+b+"\""}}
 }
 for(const b of ["sbi","irs","dhl"])if(toks.includes(b))return {brand:b,why:"contains \""+b+"\" but is not an official "+b+" domain"};
 return null;
}
if(typeof module!=="undefined")module.exports={lookalike,regDomain,BRANDS};
