/**
 * The approval window for macOS and Windows: a card in the bottom-right corner that is shown on top but never takes the
 * keyboard or moves the mouse, so someone typing can't answer it by accident. Only a click answers it: there are no
 * keyboard shortcuts, and Run stays disabled for a moment in case the window appears under the pointer.
 *
 * Both scripts are fixed text. What to show reaches them as data (an ApprovalPrompt as JSON, in argv or the environment)
 * and is only ever set as the text of a control. They print RUN only when the user clicks Run.
 */
export interface ApprovalPrompt {
  title: string;
  requester: string;
  reason: string; // the agent's own words; empty if it gave none
  details: { label: string; value: string }[];
  warning?: string;
  note?: string;
}

/** Plain text, for dialogs that can't lay the parts out. */
export function promptText(p: ApprovalPrompt): string {
  return [
    p.title, '',
    p.reason ? `${p.requester} says: ${p.reason}` : 'No explanation was given.',
    ...(p.reason ? ['(Not checked by LLLanyard. Make sure it matches what is below.)'] : []), '',
    ...p.details.map((d) => `${d.label}: ${d.value}`),
    ...(p.warning ? ['', `WARNING: ${p.warning}`] : []),
    ...(p.note ? ['', p.note] : []),
  ].join('\n');
}

/** JavaScript for Automation (`osascript -l JavaScript`). Arguments: the prompt as JSON, timeout in seconds. */
export const MAC_PROMPT = `
ObjC.import('Cocoa');
function run(argv) {
  var p = JSON.parse(argv[0]), timeout = Number(argv[1]);
  var app = $.NSApplication.sharedApplication;
  app.setActivationPolicy($.NSApplicationActivationPolicyAccessory);
  var answer = null;
  ObjC.registerSubclass({ name: 'LLYTarget', methods: {
    'allow:': { types: ['void', ['id']], implementation: function () { answer = 'RUN'; } },
    'deny:': { types: ['void', ['id']], implementation: function () { answer = 'DENY'; } },
  } });
  var target = $.LLYTarget.alloc.init;

  var W = 420, PAD = 20, inner = W - 2 * PAD;
  var sys = function (size, weight) { return $.NSFont.systemFontOfSizeWeight(size, weight || 0); };
  var muted = $.NSColor.secondaryLabelColor, ink = $.NSColor.labelColor, accent = $.NSColor.colorWithSRGBRedGreenBlueAlpha(0.06, 0.42, 0.74, 1);
  var label = function (text, font, color, width) {
    var f = $.NSTextField.wrappingLabelWithString($(text));
    f.font = font; f.textColor = color; f.selectable = false;
    f.preferredMaxLayoutWidth = width || inner;
    f.setFrameSize($.NSMakeSize(width || inner, Math.ceil(f.fittingSize.height)));
    return f;
  };
  var box = function (w, h, fill, border, radius) {
    var b = $.NSBox.alloc.initWithFrame($.NSMakeRect(0, 0, w, h));
    b.boxType = 4; b.titlePosition = 0; b.cornerRadius = radius; b.fillColor = fill;
    b.borderColor = border; b.borderWidth = 1; b.contentViewMargins = $.NSMakeSize(0, 0);
    return b;
  };
  var clear = $.NSColor.clearColor;

  var styled = function (s, attrs) {
    var text = $.NSMutableAttributedString.alloc.init;
    text.replaceCharactersInRangeWithString($.NSMakeRange(0, 0), $(s));
    var all = $.NSMakeRange(0, text.length);
    Object.keys(attrs).forEach(function (k) { text.addAttributeValueRange($(k), attrs[k], all); });
    return text;
  };

  // Details: a small caption above each value, the value in a fixed-width font.
  var boxW = inner, textW = boxW - 24;
  var rich = $.NSMutableAttributedString.alloc.init;
  var add = function (s, font, color) {
    rich.appendAttributedString(styled(s, { NSFont: font, NSColor: color }));
  };
  p.details.forEach(function (d, i) {
    add((i ? '\\n' : '') + d.label.toUpperCase() + '\\n', sys(10, 0.3), muted);
    add(d.value + (i < p.details.length - 1 ? '\\n' : ''), $.NSFont.monospacedSystemFontOfSizeWeight(11.5, 0), ink);
  });
  var text = $.NSTextView.alloc.initWithFrame($.NSMakeRect(0, 0, textW, 10));
  text.editable = false; text.selectable = false; text.drawsBackground = false;
  text.textContainer.lineFragmentPadding = 0;
  text.textStorage.setAttributedString(rich);
  text.layoutManager.ensureLayoutForTextContainer(text.textContainer);
  var textH = Math.ceil(text.layoutManager.usedRectForTextContainer(text.textContainer).size.height);
  var viewH = Math.min(textH, 190), more = textH > viewH;
  text.setFrameSize($.NSMakeSize(textW, textH));
  var scroll = $.NSScrollView.alloc.initWithFrame($.NSMakeRect(12, 10, textW, viewH));
  scroll.documentView = text; scroll.hasVerticalScroller = more; scroll.drawsBackground = false;
  var details = box(boxW, viewH + 20, $.NSColor.quaternaryLabelColor.colorWithAlphaComponent(0.08), $.NSColor.separatorColor, 8);
  details.contentView.addSubview(scroll);

  // Top to bottom: [view, gap above it]
  var rows = [];
  var head = $.NSView.alloc.initWithFrame($.NSMakeRect(0, 0, inner, 18));
  var icon = $.NSImageView.imageViewWithImage($.NSImage.imageWithSystemSymbolNameAccessibilityDescription($('lock.shield.fill'), $('LLLanyard')));
  icon.contentTintColor = accent; icon.setFrame($.NSMakeRect(0, 0, 18, 18));
  head.addSubview(icon);
  var brand = label('LLLanyard  ·  approval needed', sys(11.5, 0.23), muted, inner - 26);
  brand.setFrameOrigin($.NSMakePoint(24, 1));
  head.addSubview(brand);
  rows.push([head, 0]);
  rows.push([label(p.title, sys(15, 0.3), ink), 12]);
  rows.push([label(p.reason || 'No explanation was given.', sys(13), p.reason ? ink : muted), 8]);
  if (p.reason) rows.push([label(p.requester + '’s own explanation, not checked by LLLanyard', sys(11), muted), 4]);
  rows.push([details, 14]);
  if (more) rows.push([label('Scroll to read all of it before you click Run.', sys(11, 0.3), $.NSColor.systemOrangeColor), 6]);
  if (p.warning) rows.push([label('⚠️  ' + p.warning, sys(12, 0.23), $.NSColor.systemOrangeColor), 10]);
  if (p.note) rows.push([label(p.note, sys(11), muted), 10]);

  var bw = (inner - 10) / 2, bh = 34;
  var bar = $.NSView.alloc.initWithFrame($.NSMakeRect(0, 0, inner, bh));
  var button = function (name, action, x, fill, border, color) {
    var back = box(bw, bh, fill, border, 8);
    back.setFrameOrigin($.NSMakePoint(x, 0));
    // The caption is its own label, centred by position; the button is an invisible click area on top.
    var caption = label(name, sys(13, 0.3), color, bw);
    caption.alignment = $.NSTextAlignmentCenter;
    caption.sizeToFit;
    var size = caption.frame.size;
    caption.setFrameOrigin($.NSMakePoint(x + (bw - size.width) / 2, (bh - size.height) / 2));
    var b = $.NSButton.buttonWithTitleTargetAction($(''), target, action);
    b.bordered = false;
    b.setFrame($.NSMakeRect(x, 0, bw, bh));
    b.refusesFirstResponder = true;
    b.accessibilityLabel = $(name);
    bar.addSubview(back); bar.addSubview(caption); bar.addSubview(b);
    return { button: b, back: back };
  };
  button('Deny', 'deny:', 0, $.NSColor.quaternaryLabelColor.colorWithAlphaComponent(0.12), $.NSColor.separatorColor, ink);
  var allow = button('Run', 'allow:', bw + 10, accent, clear, $.NSColor.whiteColor);
  var arm = function (on) { allow.button.enabled = on; allow.back.fillColor = on ? accent : accent.colorWithAlphaComponent(0.4); };
  arm(false);
  rows.push([bar, 16]);

  var H = rows.reduce(function (h, r) { return h + r[1] + r[0].frame.size.height; }, 2 * PAD);
  // Borderless, non-activating panel: it can't become the key window.
  var panel = $.NSPanel.alloc.initWithContentRectStyleMaskBackingDefer($.NSMakeRect(0, 0, W, H), 128, $.NSBackingStoreBuffered, false);
  panel.releasedWhenClosed = false;
  panel.hidesOnDeactivate = false;
  panel.becomesKeyOnlyIfNeeded = true;
  panel.level = $.NSStatusWindowLevel;
  panel.collectionBehavior = 1 | 256; // every desktop, and over full-screen apps
  panel.opaque = false; panel.backgroundColor = clear; panel.hasShadow = true;
  var card = box(W, H, $.NSColor.windowBackgroundColor, $.NSColor.separatorColor, 14);
  var view = card.contentView;
  var y = H - PAD;
  rows.forEach(function (r) {
    y -= r[1] + r[0].frame.size.height;
    r[0].setFrameOrigin($.NSMakePoint(PAD, y));
    view.addSubview(r[0]);
  });
  panel.contentView = card;

  var screen = $.NSScreen.mainScreen.visibleFrame;
  panel.setFrameOrigin($.NSMakePoint(screen.origin.x + screen.size.width - W - 16, screen.origin.y + 16));
  app.finishLaunching;
  panel.orderFrontRegardless;
  var sound = $.NSSound.soundNamed($('Glass'));
  if (!sound.isNil()) sound.play;

  var start = Date.now(), armed = false;
  while (answer === null && Date.now() - start < timeout * 1000) {
    if (!armed && Date.now() - start > 1500) { armed = true; arm(true); }
    var event = app.nextEventMatchingMaskUntilDateInModeDequeue(0xFFFFFFFF, $.NSDate.dateWithTimeIntervalSinceNow(0.1), $.NSDefaultRunLoopMode, true);
    if (!event.isNil()) app.sendEvent(event);
  }
  panel.orderOut(null);
  return answer === 'RUN' ? 'RUN' : 'DENY';
}
`;

// {name} is a theme colour, filled in when the script runs.
const WIN_XAML = `<Window xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation' xmlns:x='http://schemas.microsoft.com/winfx/2006/xaml'
  Title='LLLanyard' Width='452' SizeToContent='Height' WindowStyle='None' AllowsTransparency='True' Background='Transparent'
  ResizeMode='NoResize' ShowInTaskbar='False' ShowActivated='False' Topmost='True' WindowStartupLocation='Manual'
  FontFamily='Segoe UI Variable Text, Segoe UI' FontSize='13' Foreground='{ink}' UseLayoutRounding='True'>
  <Window.Resources>
    <Style TargetType='Button'>
      <Setter Property='Focusable' Value='False'/><Setter Property='Height' Value='36'/><Setter Property='FontWeight' Value='SemiBold'/>
      <Setter Property='Template'><Setter.Value><ControlTemplate TargetType='Button'>
        <Border x:Name='b' CornerRadius='6' Background='{TemplateBinding Background}' BorderBrush='{TemplateBinding BorderBrush}' BorderThickness='1'>
          <ContentPresenter HorizontalAlignment='Center' VerticalAlignment='Center'/></Border>
        <ControlTemplate.Triggers>
          <Trigger Property='IsMouseOver' Value='True'><Setter TargetName='b' Property='Opacity' Value='0.85'/></Trigger>
          <Trigger Property='IsEnabled' Value='False'><Setter TargetName='b' Property='Opacity' Value='0.4'/></Trigger>
        </ControlTemplate.Triggers>
      </ControlTemplate></Setter.Value></Setter>
    </Style>
  </Window.Resources>
  <Border Margin='16' Padding='20' CornerRadius='12' Background='{card}' BorderBrush='{line}' BorderThickness='1'>
    <Border.Effect><DropShadowEffect BlurRadius='18' ShadowDepth='3' Direction='270' Opacity='0.35'/></Border.Effect>
    <StackPanel>
      <StackPanel Orientation='Horizontal'>
        <TextBlock Text='&#xEA18;' FontFamily='Segoe MDL2 Assets' FontSize='15' Foreground='{accent}' VerticalAlignment='Center'/>
        <TextBlock Text='LLLanyard  &#183;  approval needed' Margin='8,0,0,0' FontSize='12' Foreground='{muted}' VerticalAlignment='Center'/>
      </StackPanel>
      <TextBlock x:Name='Heading' Margin='0,12,0,0' FontSize='16' FontWeight='SemiBold' TextWrapping='Wrap'/>
      <TextBlock x:Name='Reason' Margin='0,8,0,0' FontSize='13.5' TextWrapping='Wrap'/>
      <TextBlock x:Name='Unchecked' Margin='0,4,0,0' FontSize='11' Foreground='{muted}' TextWrapping='Wrap'/>
      <Border Margin='0,14,0,0' Padding='12,10' CornerRadius='8' Background='{well}' BorderBrush='{line}' BorderThickness='1'>
        <ScrollViewer x:Name='Scroll' MaxHeight='190' VerticalScrollBarVisibility='Auto' Focusable='False'><StackPanel x:Name='Details'/></ScrollViewer>
      </Border>
      <TextBlock x:Name='More' Text='Scroll to read all of it before you click Run.' Margin='0,6,0,0' FontSize='11' FontWeight='SemiBold' Foreground='{warn}' Visibility='Collapsed'/>
      <TextBlock x:Name='Warning' Margin='0,10,0,0' FontSize='12' FontWeight='SemiBold' Foreground='{warn}' TextWrapping='Wrap'/>
      <TextBlock x:Name='Note' Margin='0,10,0,0' FontSize='11' Foreground='{muted}' TextWrapping='Wrap'/>
      <Grid Margin='0,16,0,0'>
        <Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition Width='10'/><ColumnDefinition/></Grid.ColumnDefinitions>
        <Button x:Name='Deny' Content='Deny' Background='{well}' BorderBrush='{line}' Foreground='{ink}'/>
        <Button x:Name='Run' Grid.Column='2' Content='Run' Background='{accent}' BorderBrush='{accent}' Foreground='White' IsEnabled='False'/>
      </Grid>
    </StackPanel>
  </Border>
</Window>`;

/** Windows PowerShell. Reads LLY_PROMPT (the prompt as JSON) and LLY_TIMEOUT (seconds). */
export const WIN_PROMPT = `
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
Add-Type -Namespace Lly -Name Native -WarningAction SilentlyContinue -MemberDefinition '[DllImport("user32.dll")] public static extern int GetWindowLong(IntPtr h, int i); [DllImport("user32.dll")] public static extern int SetWindowLong(IntPtr h, int i, int v);'
$p = $env:LLY_PROMPT | ConvertFrom-Json
$light = 1
try { $light = (Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize').AppsUseLightTheme } catch {}
if ($light -eq 0) { $theme = @{ card = '#2B2B2B'; well = '#202020'; line = '#454545'; ink = '#FFFFFF'; muted = '#B4B4B4'; accent = '#0F6CBD'; warn = '#FFB84D' } }
else { $theme = @{ card = '#FFFFFF'; well = '#F5F5F5'; line = '#E0E0E0'; ink = '#1B1B1B'; muted = '#616161'; accent = '#0F6CBD'; warn = '#B25E00' } }
$xaml = '${WIN_XAML.replace(/'/g, "''")}'
foreach ($k in $theme.Keys) { $xaml = $xaml.Replace('{' + $k + '}', $theme[$k]) }
$w = [System.Windows.Markup.XamlReader]::Parse($xaml)
function ctl($n) { $w.FindName($n) }
function show($n, $t) { $c = ctl $n; if ($t) { $c.Text = $t } else { $c.Visibility = 'Collapsed' } }
(ctl 'Heading').Text = $p.title
if ($p.reason) { (ctl 'Reason').Text = $p.reason; (ctl 'Unchecked').Text = $p.requester + [char]0x2019 + 's own explanation, not checked by LLLanyard' }
else { (ctl 'Reason').Text = 'No explanation was given.'; (ctl 'Unchecked').Visibility = 'Collapsed' }
show 'Warning' $p.warning
show 'Note' $p.note
$first = $true
foreach ($d in $p.details) {
  $cap = New-Object System.Windows.Controls.TextBlock
  $cap.Text = ([string]$d.label).ToUpper(); $cap.FontSize = 10; $cap.FontWeight = 'SemiBold'; $cap.Foreground = $theme.muted
  if (-not $first) { $cap.Margin = '0,8,0,0' }
  $val = New-Object System.Windows.Controls.TextBlock
  $val.Text = $d.value; $val.FontFamily = 'Cascadia Mono, Consolas'; $val.FontSize = 12; $val.TextWrapping = 'Wrap'; $val.Margin = '0,2,0,0'
  [void](ctl 'Details').Children.Add($cap); [void](ctl 'Details').Children.Add($val)
  $first = $false
}
$script:answer = 'DENY'
(ctl 'Run').add_Click({ $script:answer = 'RUN'; $w.Close() })
(ctl 'Deny').add_Click({ $w.Close() })
# WS_EX_NOACTIVATE (never takes focus) and WS_EX_TOOLWINDOW (not in Alt+Tab).
$w.add_SourceInitialized({
  $h = (New-Object System.Windows.Interop.WindowInteropHelper $w).Handle
  [void][Lly.Native]::SetWindowLong($h, -20, ([Lly.Native]::GetWindowLong($h, -20) -bor 0x08000080))
})
$place = { $a = [System.Windows.SystemParameters]::WorkArea; $w.Left = $a.Right - $w.ActualWidth; $w.Top = $a.Bottom - $w.ActualHeight }
$arm = New-Object System.Windows.Threading.DispatcherTimer
$arm.Interval = [TimeSpan]::FromMilliseconds(1500)
$arm.add_Tick({ (ctl 'Run').IsEnabled = $true; $arm.Stop() })
$limit = New-Object System.Windows.Threading.DispatcherTimer
$limit.Interval = [TimeSpan]::FromSeconds([int]$env:LLY_TIMEOUT)
$limit.add_Tick({ $limit.Stop(); $w.Close() })
$w.add_SizeChanged($place)
$w.add_ContentRendered({
  & $place
  if ((ctl 'Scroll').ScrollableHeight -gt 0) { (ctl 'More').Visibility = 'Visible' }
  $arm.Start(); $limit.Start(); [System.Media.SystemSounds]::Asterisk.Play()
})
[void]$w.ShowDialog()
$script:answer
`;
