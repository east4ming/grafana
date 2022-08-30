//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// This file is autogenerated. DO NOT EDIT.
//
// To regenerate, run "make gen-cue" from the repository root.
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

import * as ui from '@grafana/schema';

export const PanelModelVersion = Object.freeze([0, 0]);


export interface PanelOptions extends ui.OptionsWithLegend, ui.OptionsWithTooltip {
  bucketOffset?: number;
  bucketSize?: number;
  combine?: boolean;
}

export const defaultPanelOptions: Partial<PanelOptions> = {
  bucketOffset: 0,
};

export interface PanelFieldConfig extends ui.AxisConfig, ui.HideableFieldConfig {
  fillOpacity?: number;
  gradientMode?: ui.GraphGradientMode;
  lineWidth?: number;
}

export const defaultPanelFieldConfig: Partial<PanelFieldConfig> = {
  fillOpacity: 80,
  gradientMode: ui.GraphGradientMode.None,
  lineWidth: 1,
};
