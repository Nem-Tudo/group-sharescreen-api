API OF https://golive.nemtudo.me

API URL: https://apigolive.nemtudo.me

Front GitHub:
https://github.com/Nem-Tudo/group-sharescreen

## Login com Discord / Google

O fluxo OAuth roda inteiro nesta API (`server/oauthRoutes.ts`) e termina no
mesmo JWT que `/auth/login` já emitia — o front só recebe o token e guarda.
Sem as variáveis abaixo, nada muda: o provedor some da lista e o botão nem
aparece no front.

| Variável | Para quê |
| --- | --- |
| `DISCORD_CLIENT_ID` / `DISCORD_CLIENT_SECRET` | Habilita o botão do Discord |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Habilita o botão do Google |
| `WEB_ORIGINS` | Origens do front que podem receber o token, separadas por vírgula (padrão: `http://localhost:3000`). É a allowlist que impede o callback de virar open redirect |
| `OAUTH_CALLBACK_BASE` | URL pública **desta** API, usada para montar o `redirect_uri`. Sem ela, é derivada do request — bom em dev, mas fixe em produção |

Exemplo de produção:

```
WEB_ORIGINS=https://golive.nemtudo.me
OAUTH_CALLBACK_BASE=https://apigolive.nemtudo.me
```

### Redirect URIs para cadastrar no provedor

- Discord (Developer Portal → OAuth2 → Redirects):
  `https://apigolive.nemtudo.me/auth/oauth/discord/callback`
- Google (Cloud Console → Credenciais → URIs de redirecionamento autorizados):
  `https://apigolive.nemtudo.me/auth/oauth/google/callback`

Em dev, os mesmos caminhos com `http://localhost:4000`.

### Como o fluxo se comporta

- **Já entrou com esse provedor antes:** entra direto na conta de sempre — o
  vínculo é pelo id do provedor, então trocar o e-mail lá fora não muda nada
  aqui.
- **Primeira vez, e o e-mail já é de uma conta daqui:** vincula os dois, mas
  só quando o provedor afirma que o e-mail é verificado. Sem isso, qualquer
  um criaria uma conta descartável com o seu e-mail e entraria na sua.
- **Primeira vez, conta nova:** o usuário escolhe usuário/nome de exibição
  (já pré-preenchidos com o nome do provedor). Nenhuma conta é criada antes
  disso — desistir no meio não deixa lixo no banco.
- **Já tem conta e quer vincular:** estando logado, o front manda o token da
  sessão no `/start` e a API prende o provedor **àquela** conta — mesmo id,
  mesmos flags, mesmo histórico. Se aquela conta do Discord/Google já for o
  acesso de outro usuário daqui, o vínculo é recusado (`identity_taken`) em
  vez de mudar de dono.

Contas criadas por login social ficam sem senha, então não entram por
`/auth/login`. `GET /auth/me` devolve `connections` (`providers` e
`hasPassword`), que é o que alimenta o painel "Conexões" na home, e
`DELETE /auth/oauth/:provider/link` desvincula um provedor — recusando
quando é o último jeito de entrar na conta.
