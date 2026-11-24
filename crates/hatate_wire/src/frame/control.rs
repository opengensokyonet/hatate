//! The frames whose payload is one integer: CANCEL_PUSH, GOAWAY and
//! MAX_PUSH_ID, all on the control stream ([RFC 9114 §7.2.3, §7.2.6,
//! §7.2.7]).
//!
//! A reader ([`codec`]) reads the frame's payload through the
//! [`FramePayload`] composed onto the stream, given the widths of the head
//! that was read; a writer writes the whole frame, its Length being the
//! width of the integer.
//!
//! [`FramePayload`]: super::payload::FramePayload
//! [RFC 9114 §7.2.3, §7.2.6, §7.2.7]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.3
use super::{FrameWidths, GoawayId, PushId};
use sakuya_var_int::VarIntField;

#[allow(missing_docs)] // The call macro also generates operation and extension trait items.
pub mod codec;

macro_rules! integer_frame {
    (
        $(#[$doc:meta])*
        $name:ident, $field:ident: $field_type:ty
    ) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $name {
            widths: FrameWidths,
            $field: VarIntField<$field_type>,
        }

        impl $name {
            /// The frame with the shortest Type and Length.
            pub const fn new($field: VarIntField<$field_type>) -> Self {
                Self::with_widths($field, FrameWidths::SHORTEST)
            }

            /// The frame with the Type and Length at `widths`. Every width
            /// holds both, so this cannot fail.
            pub const fn with_widths($field: VarIntField<$field_type>, widths: FrameWidths) -> Self {
                Self { widths, $field }
            }

            #[doc = concat!("The ", stringify!($field), " field.")]
            pub const fn $field(&self) -> VarIntField<$field_type> {
                self.$field
            }

            /// The widths of the Type and Length.
            pub const fn widths(&self) -> FrameWidths {
                self.widths
            }

            /// The number of bytes of the whole frame.
            pub const fn encoded_len(&self) -> usize {
                self.widths.type_width().encoded_len()
                    + self.widths.length_width().encoded_len()
                    + self.$field.encoded_len()
            }
        }
    };
}

integer_frame! {
    /// A CANCEL_PUSH frame (type 0x03, [RFC 9114 §7.2.3]): the push with
    /// this ID is cancelled.
    ///
    /// [RFC 9114 §7.2.3]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.3
    CancelPushFrame, push_id: PushId
}

integer_frame! {
    /// A GOAWAY frame (type 0x07, [RFC 9114 §7.2.6]): the sender begins to
    /// shut the connection down, up to the [`GoawayId`].
    ///
    /// [RFC 9114 §7.2.6]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.6
    GoawayFrame, id: GoawayId
}

integer_frame! {
    /// A MAX_PUSH_ID frame (type 0x0d, [RFC 9114 §7.2.7]): the largest push
    /// ID the client permits.
    ///
    /// [RFC 9114 §7.2.7]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.7
    MaxPushIdFrame, push_id: PushId
}
