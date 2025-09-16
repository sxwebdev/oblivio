import { Store } from "@tanstack/store";

export type CryptoState = {
  vmk?: Uint8Array;
  kSearch?: Uint8Array;
};

export const cryptoStore = new Store<CryptoState>({});

export function zeroizeCrypto() {
  const st = cryptoStore.state;
  if (st.vmk) st.vmk.fill(0);
  if (st.kSearch) st.kSearch.fill(0);
  cryptoStore.setState({ vmk: undefined, kSearch: undefined });
}
