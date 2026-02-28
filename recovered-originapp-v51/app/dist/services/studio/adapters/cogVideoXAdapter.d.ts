import { StudioAdapterInput, StudioAdapterResult } from '../../../types/studio';
import { StudioModelAdapter } from './adapterTypes';
export declare class CogVideoXAdapter implements StudioModelAdapter {
    readonly model: "cogvideox";
    run(input: StudioAdapterInput): Promise<StudioAdapterResult>;
}
//# sourceMappingURL=cogVideoXAdapter.d.ts.map