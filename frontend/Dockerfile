FROM node:20-alpine AS builder

RUN apk add --no-cache libc6-compat

WORKDIR /app

COPY package.json package-lock.json ./

RUN npm ci --no-audit

COPY . .

RUN npm run build

FROM nginx:1.25-alpine

RUN apk add --no-cache curl

RUN rm -rf /usr/share/nginx/html/*

COPY --from=builder /app/dist /usr/share/nginx/html

COPY nginx.conf /etc/nginx/conf.d/default.conf

RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

RUN chown -R nextjs:nodejs /usr/share/nginx/html

EXPOSE 3000

CMD ["nginx", "-g", "daemon off;"]