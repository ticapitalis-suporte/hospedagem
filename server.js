const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;
const PUB = path.join(ROOT, 'public');
const DATA = path.join(ROOT, 'data');
const ARQ_SOLIC = path.join(DATA, 'solicitacoes.json');
const ARQ_SESSOES = path.join(DATA, 'sessoes.json');
const ARQ_SETORES = path.join(DATA, 'setores.json');
const config = JSON.parse(fs.readFileSync(path.join(ROOT, 'config.json'), 'utf8'));
const PORT = process.env.PORT || config.port || 8002;
const ADMIN_TOKEN = String(config.adminToken || '');
const PAINEL_URL = (process.env.PAINEL_URL || config.painelUrl || 'http://localhost:1945').replace(/\/$/, '');
const SETORES = ['TI', 'DP', 'FISCAL', 'RH', 'CONTADOR', 'FINANCEIRO'];
const TIPOS = new Set(['software', 'hardware', 'portal']);
const EXT = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.png': 'image/png', '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon', '.json': 'application/json; charset=utf-8',
  '.webp': 'image/webp', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg'
};

function loadFile(p, fb) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (e) { return fb; }
}
function saveFile(p, v) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const tmp = p + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(v, null, 2));
  fs.renameSync(tmp, p);
}
function load() { return loadFile(ARQ_SOLIC, []); }
function save(list) { saveFile(ARQ_SOLIC, list); }
function send(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > 16384) { reject(new Error('payload grande demais')); req.destroy(); }
      else chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
function isAdmin(req) {
  const t = String(req.headers['x-admin-token'] || '');
  if (!t || !ADMIN_TOKEN) return false;
  const a = crypto.createHash('sha256').update(t).digest();
  const b = crypto.createHash('sha256').update(ADMIN_TOKEN).digest();
  return crypto.timingSafeEqual(a, b);
}

const MANUT_ARQ = process.env.MANUTENCAO_ARQUIVO || config.manutencaoArquivo || '';
const COOKIE_BYPASS = 'capitalis_admin';
function lerManutencao() {
  if (!MANUT_ARQ) return null;
  try {
    const m = JSON.parse(fs.readFileSync(MANUT_ARQ, 'utf8'));
    if (!m || typeof m.segredo !== 'string' || !m.ativo) return null;
    return m;
  } catch (e) { return null; }
}
function cookieBypass(req) {
  const c = String(req.headers.cookie || '');
  const m = c.match(/(?:^|;\s*)capitalis_admin=([^;]+)/);
  return m ? m[1] : '';
}
function bypassValido(req, m) {
  const valor = cookieBypass(req);
  if (!valor || !m || !m.segredo) return false;
  const esperado = crypto.createHmac('sha256', String(m.segredo)).update('bypass').digest('hex');
  const a = crypto.createHash('sha256').update(valor).digest();
  const b = crypto.createHash('sha256').update(esperado).digest();
  return crypto.timingSafeEqual(a, b);
}
const CHAVE_MANUT = 'painel-servicos';
function emManutencao(req) {
  const m = lerManutencao();
  if (!m || !m.ativo[CHAVE_MANUT]) return false;
  return !bypassValido(req, m);
}
function htmlManutencao(host) {
  const alvo = 'http://' + String(host || 'localhost').split(':')[0] + ':8003/';
  return '<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">' +
    '<title>Em manutenção · Capitalis</title><style>' +
    'body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0e1116;color:#e7ecf2;' +
    'font:16px/1.6 "Segoe UI",system-ui,sans-serif;text-align:center;padding:24px}' +
    '.c{max-width:520px}.c img{width:78px;margin-bottom:16px}' +
    'h1{font-size:26px;margin:0 0 10px}p{color:#95a1b3;margin:0 0 6px}' +
    '.selo{display:inline-block;margin-top:20px;font-size:13px;color:#d8cf4e;border:1px solid #3d3a1c;border-radius:20px;padding:6px 16px;text-decoration:none}' +
    '</style></head><body><div class="c">' +
    '<img src="/logo-capitalis.png" alt="Capitalis">' +
    '<h1>Estamos em manutenção</h1>' +
    '<p>O sistema está temporariamente indisponível para uma atualização.</p>' +
    '<p>Volte em instantes, obrigado pela compreensão.</p>' +
    '<a class="selo" href="' + alvo + '">Área do administrador</a>' +
    '</div></body></html>';
}

let sessoes = loadFile(ARQ_SESSOES, {});
let setores = loadFile(ARQ_SETORES, {});
{
  const now = Date.now(); let dirty = false;
  for (const k of Object.keys(sessoes)) {
    if (!sessoes[k] || now - (sessoes[k].criado || 0) > 7 * 86400000) { delete sessoes[k]; dirty = true; }
  }
  if (dirty) saveFile(ARQ_SESSOES, sessoes);
}
function sessao(req) {
  const t = String(req.headers['x-session'] || '');
  if (!t || !sessoes[t]) return null;
  return { token: t, label: sessoes[t].label };
}
function setorDe(label) { return setores[String(label || '').trim().toLowerCase()] || null; }
function ehJoao(label) { return /bento/i.test(String(label || '')); }

let cacheUsers = { ts: 0, list: null };
async function painelUsuarios() {
  if (cacheUsers.list && Date.now() - cacheUsers.ts < 60000) return cacheUsers.list;
  const ctl = new AbortController();
  const to = setTimeout(() => ctl.abort(), 5000);
  try {
    const r = await fetch(PAINEL_URL + '/api/usuarios', { signal: ctl.signal });
    if (!r.ok) throw new Error('painel respondeu ' + r.status);
    const list = await r.json();
    if (!Array.isArray(list)) throw new Error('resposta inválida');
    cacheUsers = { ts: Date.now(), list };
    return list;
  } finally { clearTimeout(to); }
}

function ymd(d) { return d.toISOString().slice(0, 10); }
function str(v, min, max) {
  const s = String(v == null ? '' : v).trim();
  if (s.length < min || s.length > max) return null;
  return s;
}
function validaData(v) {
  const s = str(v, 10, 10);
  if (!s || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return null;
  if (s < ymd(new Date())) return null;
  return s;
}
function serveStatic(res, urlPath) {
  let name;
  if (urlPath === '/' || urlPath === '/index.html' || urlPath === '/solicitante' || urlPath === '/recebedor') name = 'index.html';
  else if (/^\/[\w.\-]+$/.test(urlPath)) name = urlPath.slice(1);
  else return send(res, 404, { erro: 'não encontrado' });
  const file = path.join(PUB, name);
  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) return send(res, 404, { erro: 'não encontrado' });
  const ext = path.extname(name).toLowerCase();
  res.writeHead(200, {
    'Content-Type': EXT[ext] || 'application/octet-stream',
    'Cache-Control': name === 'index.html' ? 'no-store' : 'public, max-age=3600'
  });
  fs.createReadStream(file).pipe(res);
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  const p = u.pathname;

  try {
    const sempreLiberado = p === '/api/health' || p === '/logo-capitalis.png' || p === '/favicon.png';
    if (!sempreLiberado && emManutencao(req)) {
      if (p.startsWith('/api/')) return send(res, 503, { erro: 'Sistema em manutenção. Volte em instantes.', manutencao: true });
      res.writeHead(503, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(htmlManutencao(req.headers.host));
    }

    if (p === '/api/health') return send(res, 200, { ok: true });

    if (p === '/api/login' && req.method === 'POST') {
      const body = JSON.parse((await readBody(req)) || '{}');
      const label = str(body.label, 1, 80);
      const senha = String(body.senha || '');
      if (!label || !senha) return send(res, 400, { erro: 'informe usuário e senha' });
      let users;
      try { users = await painelUsuarios(); }
      catch (e) { return send(res, 502, { erro: 'Painel de clientes indisponível. Tente novamente.' }); }
      const u2 = users.find(x =>
        String(x.label || '').trim().toLowerCase() === label.toLowerCase() &&
        String(x.password || '') === senha
      );
      if (!u2) return send(res, 401, { erro: 'Usuário ou senha incorretos', code: 'login' });
      const nome = String(u2.label).trim();
      const token = crypto.randomBytes(24).toString('hex');
      sessoes[token] = { label: nome, criado: Date.now() };
      saveFile(ARQ_SESSOES, sessoes);
      const setor = setorDe(nome);
      return send(res, 200, { ok: true, token, label: nome, setor, precisaSetor: !setor, podeContador: ehJoao(nome) });
    }

    if (p === '/api/me' && req.method === 'GET') {
      const s = sessao(req);
      if (!s) return send(res, 401, { erro: 'não conectado', code: 'sessao' });
      const setor = setorDe(s.label);
      return send(res, 200, { ok: true, label: s.label, setor, precisaSetor: !setor, podeContador: ehJoao(s.label) });
    }

    if (p === '/api/setor' && req.method === 'POST') {
      const s = sessao(req);
      if (!s) return send(res, 401, { erro: 'não conectado', code: 'sessao' });
      const body = JSON.parse((await readBody(req)) || '{}');
      const setor = String(body.setor || '').trim().toUpperCase();
      if (!SETORES.includes(setor)) return send(res, 400, { erro: 'setor inválido' });
      if (setor === 'CONTADOR' && !ehJoao(s.label)) return send(res, 403, { erro: 'O setor CONTADOR está disponível apenas no login do João Bento.' });
      setores[s.label.trim().toLowerCase()] = setor;
      saveFile(ARQ_SETORES, setores);
      return send(res, 200, { ok: true, setor });
    }

    if (p === '/api/logout' && req.method === 'POST') {
      const t = String(req.headers['x-session'] || '');
      if (t && sessoes[t]) { delete sessoes[t]; saveFile(ARQ_SESSOES, sessoes); }
      return send(res, 200, { ok: true });
    }

    if (p === '/api/auth' && req.method === 'POST') {
      if (!isAdmin(req)) return send(res, 401, { erro: 'token de recebedor inválido', code: 'token' });
      const sa = sessao(req);
      if (!sa) return send(res, 401, { erro: 'não conectado', code: 'sessao' });
      if (setorDe(sa.label) !== 'TI') return send(res, 403, { erro: 'Apenas o setor TI recebe as solicitações.', code: 'setor' });
      return send(res, 200, { ok: true });
    }

    if (p === '/api/solicitacoes' && req.method === 'GET') {
      const items = load().sort((a, b) => (b.criado_em || '').localeCompare(a.criado_em || ''));
      return send(res, 200, { ok: true, items });
    }

    if (p === '/api/solicitacoes' && req.method === 'POST') {
      const s = sessao(req);
      if (!s) return send(res, 401, { erro: 'faça login para criar solicitação', code: 'sessao' });
      const body = JSON.parse((await readBody(req)) || '{}');
      const nome = str(body.nome, 2, 120);
      const contato = str(body.contato, 2, 120);
      const descricao = str(body.descricao, 3, 1000);
      const tipo = String(body.tipo || '');
      let prazo = parseInt(body.prazo_dias, 10);
      if (!nome || !contato || !descricao || !TIPOS.has(tipo)) return send(res, 400, { erro: 'preencha nome, contato, tipo, descrição e prazo' });
      if (!Number.isFinite(prazo) || prazo < 1 || prazo > 365) prazo = 7;
      const item = {
        id: 'SV-' + crypto.randomBytes(3).toString('hex').toUpperCase(),
        nome, contato, tipo, descricao, prazo_dias: prazo,
        solicitante: s.label, setor: setorDe(s.label),
        status: 'pendente', criado_em: new Date().toISOString(),
        aceito_em: null, entrega_prevista: null, entregue_em: null, motivo: null
      };
      const list = load(); list.push(item); save(list);
      return send(res, 201, { ok: true, item });
    }

    const m = p.match(/^\/api\/solicitacoes\/(SV-[A-F0-9]+)\/(aceitar|entregue|recusar|entrega)$/);
    if (m && req.method === 'POST') {
      if (!isAdmin(req)) return send(res, 401, { erro: 'token de recebedor inválido', code: 'token' });
      const sa = sessao(req);
      if (!sa) return send(res, 401, { erro: 'não conectado', code: 'sessao' });
      if (setorDe(sa.label) !== 'TI') return send(res, 403, { erro: 'Apenas o setor TI recebe as solicitações.', code: 'setor' });
      const [, id, acao] = m;
      const list = load();
      const item = list.find(x => x.id === id);
      if (!item) return send(res, 404, { erro: 'solicitação não encontrada' });
      const body = JSON.parse((await readBody(req)) || '{}');

      if (acao === 'aceitar') {
        if (item.status !== 'pendente') return send(res, 400, { erro: 'solicitação não está pendente' });
        const entrega = validaData(body.entrega);
        if (!entrega) return send(res, 400, { erro: 'escolha uma data de entrega válida (hoje ou futura)' });
        const agora = new Date().toISOString();
        item.status = 'aceita';
        item.aceito_em = agora;
        item.entrega_prevista = entrega;
        const dAceite = Date.parse(agora.slice(0, 10) + 'T00:00:00Z');
        const dEnt = Date.parse(entrega + 'T00:00:00Z');
        item.prazo_dias = Math.max(0, Math.round((dEnt - dAceite) / 86400000));
      } else if (acao === 'entregue') {
        if (item.status !== 'aceita') return send(res, 400, { erro: 'solicitação precisa estar aceita' });
        item.status = 'entregue';
        item.entregue_em = new Date().toISOString();
      } else if (acao === 'recusar') {
        if (item.status !== 'pendente') return send(res, 400, { erro: 'solicitação não está pendente' });
        item.status = 'recusada';
        item.motivo = str(body.motivo, 0, 300) || null;
      } else if (acao === 'entrega') {
        if (item.status !== 'aceita') return send(res, 400, { erro: 'solicitação precisa estar aceita' });
        const entrega = validaData(body.entrega);
        if (!entrega) return send(res, 400, { erro: 'data de entrega inválida' });
        item.entrega_prevista = entrega;
        const dAceite = Date.parse(item.aceito_em.slice(0, 10) + 'T00:00:00Z');
        const dEnt = Date.parse(entrega + 'T00:00:00Z');
        item.prazo_dias = Math.max(0, Math.round((dEnt - dAceite) / 86400000));
      }
      save(list);
      return send(res, 200, { ok: true, item });
    }

    if (p.startsWith('/api/')) return send(res, 404, { erro: 'rota não encontrada' });
    if (req.method === 'GET') return serveStatic(res, p);
    return send(res, 405, { erro: 'método não permitido' });
  } catch (e) {
    return send(res, e.message === 'payload grande demais' ? 413 : 400, { erro: e.message || 'erro' });
  }
});

server.listen(PORT, () => console.log('Gestão de Serviços Capitalis na porta ' + PORT + ' (painel: ' + PAINEL_URL + ')'));
