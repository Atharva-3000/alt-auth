import { Ratelimit } from "@unkey/ratelimit"

const unkey = new Ratelimit({
  rootKey: process.env.UNKEY,
  namespace: "alt-auth",
  limit:2,
  duration: "5m",
  async: true
})


export default unkey